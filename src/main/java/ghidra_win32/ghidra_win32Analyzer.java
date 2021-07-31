/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra_win32;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ghidra_win32Analyzer extends AbstractAnalyzer {
	
	private Win32Data m_database;
	private Program m_program;
	private TaskMonitor m_monitor;
	

	public ghidra_win32Analyzer() {

		// TODO: Name the analyzer and give it a description.
		super("Win32 API Analyzer", "Analyze Win32 functions", AnalyzerType.BYTE_ANALYZER);
		m_database = new Win32Data();
		setPriority(new AnalysisPriority(10000000));
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equals(PeLoader.PE_NAME);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// options.registerOption("Option name goes here", false, null, "Option description goes here");
	}
	
	private ArrayList<Function> getFuncs() {
		ArrayList<Function> funcs = new ArrayList<>();
		String[] support_dlls = {
				"USER32.DLL",
				"KERNEL32.DLL"
		};
		
		FunctionManager fm = m_program.getFunctionManager();
		for(Function func : fm.getExternalFunctions()) {
			String lib = func.getExternalLocation().getLibraryName();
			Boolean is_winapi_lib = false;
			for(String dll : support_dlls) {
				if(dll.equals(lib)) {
					is_winapi_lib = true;
					break;
				}
			}
			if(!is_winapi_lib)
				continue;
			
			if(!m_database.contains(func.getName()))
				continue;
			
			System.out.println("[Ghidra Win32 A] Function: " + func.getName() + " in " + lib);
			funcs.add(func);
		}
		
		return funcs;
	}
	
	private ArrayList<Address> getCalls(Function func) {
		ArrayList<Address> calls = new ArrayList<>();
		
		ReferenceManager rm = m_program.getReferenceManager();
		for(Reference ref : rm.getReferencesTo(func.getEntryPoint())) {
			calls.add(ref.getFromAddress());
			System.out.println("[Ghidra Win32 A] " + ref.getFromAddress() + " call ->" + func.getName());
		}
		
		return calls;
	}
	
	private long getRegisterValue(Function func, Address call, Register register) {
		SymbolicPropogator sym_eval = new SymbolicPropogator(m_program);
		Function caller = m_program.getListing().getFunctionContaining(call);
		ConstantPropagationContextEvaluator evaluate = new ConstantPropagationContextEvaluator(true);
		
		try {
			sym_eval.flowConstants(caller.getEntryPoint(), caller.getBody(), evaluate, false, m_monitor);
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			return -1;
		}
		
		Value resault = sym_eval.getRegisterValue(call, register);
		if(resault != null)
			return resault.getValue();
		
		return -1;
	}
	
	private long getStackValue(Function func, Address call, Parameter param) {
		Instruction inst = m_program.getListing().getInstructionAt(call);
		if(inst == null)
			return -1;
		
		Address init = call;
		Instruction curr = inst.getPrevious();
		while(curr != null) {
			if(!curr.getFlowType().toString().equals("FALL_THROUGH"))
				break;
			init = curr.getAddress();
			curr = curr.getPrevious();
		}
		
		EmulatorHelper emulator_helper = new EmulatorHelper(m_program);
		emulator_helper.setBreakpoint(call);
		emulator_helper.writeRegister(emulator_helper.getPCRegister(), new BigInteger(init.toString(), 16));
		
		long stackOffset = (call.getAddressSpace().getMaxAddress().getOffset() >> 1) -  0x7fff;
		emulator_helper.writeRegister(emulator_helper.getStackPointerRegister(), stackOffset);
		
		Address last = null;
		BigInteger value = BigInteger.valueOf(-1);
		while(true) {
			Address address = emulator_helper.getExecutionAddress();
			CodeUnit current = m_program.getListing().getCodeUnitAt(address);
			
			if(address.equals(last)) {
				Address go_to = current.getMaxAddress().next();
				emulator_helper.writeRegister(emulator_helper.getPCRegister(), new BigInteger(go_to.toString(), 16));
				continue;
			}
			else
				last = address;
			
			if(address.equals(call)) {
				int start = param.getStackOffset() - param.getLength();
				try {
					value = emulator_helper.readStackValue(start, param.getLength(), true);
				} catch (Exception e) {
					value = BigInteger.valueOf(-1);
					break;
				}
				break;
			}
		}
		
		return value.longValue();
	}
	
	private long getParameterValue(Function func, Address call, int n) {
		Parameter param = func.getParameter(n);
		if(param != null) {
			if(param.isRegisterVariable())
				return getRegisterValue(func, call, param.getRegister());
			else if(param.isStackVariable())
				return getStackValue(func, call, param);
		}
		return -1;
	}
	
	public String getConstants(Function func, int nth_param, long value){
		if(value == -1)
			return null;
		String param_name = m_database.getNthParameterName(func.getName(), nth_param);
		ArrayList<Win32Data.Constant> pos_constants = m_database.getParameterReplacements(func.getName(), param_name);
		if(pos_constants == null || pos_constants.isEmpty())
			return null;
		
		String constants_str = "";
		ArrayList<String> constants = new ArrayList<>();
		for(Win32Data.Constant con : pos_constants) {
			if(con.value == -1)
				continue;
			else if(con.value == 0 && con.value == value)
				constants.add(con.name);
			else if((con.value & value) == con.value)
				constants.add(con.name);
		}
		
		for(String con : constants) {
			if(!constants_str.isBlank())
				constants_str += '|';
			constants_str += con;
		}
		
		return constants_str;
	}
	
	public void updateEquates(Address call, String constants, long value) {
		if(value == -1)
			return;
		Instruction inst = m_program.getListing().getInstructionAt(call);
		Boolean done = false;
		while(!done && inst != null) {
			for(int i = 0; i < inst.getNumOperands(); i++) {
				if(inst.getOperandType(i) == OperandType.SCALAR) {
					long scalar = inst.getScalar(i).getUnsignedValue();
					if(scalar == value) {
						SetEquateCmd cmd = new SetEquateCmd(constants, inst.getAddress(), i, value);
						cmd.applyTo(m_program);
						System.out.println("Applied Equate:" + constants + " to " + inst.getAddress());
						done = true;
						break;
					}
				}
			}
			
			inst = inst.getPrevious();
			if (inst == null || inst.getFlowType().toString() != "FALL_THROUGH") 
				break;
		}
		
	}
	

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		System.out.println("[Ghidra Win32 A] Starting Analysis...");
		
		m_program = program;
		m_monitor = monitor;
		
		for(Function func : getFuncs()) {
			ArrayList<Address> calls = getCalls(func);
			for(Address call : calls) {
				Function caller = m_program.getListing().getFunctionContaining(call);
				if(caller == null)
					continue;
				
				System.out.println("Analyzing call at " + call + " " + func.getName() + ", caller : " + m_program.getListing().getFunctionContaining(call).getName());
				for(int i = 0; i < func.getParameterCount(); i++) {
					long value = getParameterValue(func, call, i);
					System.out.println("param" + (i+1) + " : " + value);
					String consts = getConstants(func, i, value);
					if(consts == null || consts.isBlank())
						continue;
					updateEquates(call, consts, value);
				}
			}
		}
		
		System.out.println("[Ghidra Win32 A] Analysis Compelete");
		
		return true;
	}

}
