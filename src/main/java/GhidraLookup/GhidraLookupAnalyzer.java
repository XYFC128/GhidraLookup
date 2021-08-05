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
package GhidraLookup;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangFuncProto;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class GhidraLookupAnalyzer extends AbstractAnalyzer {
	
	private Win32Data m_database;
	private Program m_program;
	private TaskMonitor m_monitor;
	private Options m_options;
	

	public GhidraLookupAnalyzer() {

		// TODO: Name the analyzer and give it a description.
		super("GhidraLookupAnalyzer", "Analyze Win32 functions", AnalyzerType.BYTE_ANALYZER);
		m_database = new Win32Data();
		setPriority(new AnalysisPriority(10000000));
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equals(PeLoader.PE_NAME);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		m_options = options;
		options.registerOption("Equates Separator", " | ", null, "If there are multiple Equates match same value, they will be separated by this separator.");
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		System.out.println("[Ghidra Win32 A] Starting Analysis...");
		
		m_program = program;
		m_monitor = monitor;
		
		HashSet<Function> callers = new HashSet<>();
		
		for(Function func : getFuncs()) {
			ArrayList<Address> calls = getCalls(func);
			for(Address call : calls) {
				Function caller = m_program.getListing().getFunctionContaining(call);
				if(caller == null)
					continue;
				callers.add(caller);
			}
		}
		
		try {
			runDecompilerAnalysis(program, callers, monitor);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("[Ghidra Win32 A] Analysis Compelete");
		
		return true;
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
			System.out.println("[Ghidra Win32 A] " + ref.getFromAddress() + " call -> " + func.getName());
		}
		
		return calls;
	}
	
	private String getConstants(String func_name, int nth_param, long value) {
		if(value == -1)
			return null;
		String param_name = m_database.getNthParameterName(func_name, nth_param);
		ArrayList<Win32Data.Constant> pos_constants = m_database.getParameterReplacements(func_name, param_name);
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
				constants_str += m_options.getString("Equates Separator", " | ");
			constants_str += con;
		}
		
		return constants_str;
	}
	
	private String getConstants(Function func, int nth_param, long value){
		return getConstants(func.getName(), nth_param, value);
	}
	
	private Boolean updateEquates(Address call, String constants, long value) {
		if(value == -1)
			return false;
		Instruction inst = m_program.getListing().getInstructionAt(call);
		Boolean done = false;
		while(!done && inst != null) {
			for(int i = 0; i < inst.getNumOperands(); i++) {
				if(inst.getOperandType(i) == OperandType.SCALAR) {
					long scalar = inst.getScalar(i).getUnsignedValue();
					if(scalar == value) {
						SetEquateCmd cmd = new SetEquateCmd(constants, inst.getAddress(), i, value);
						cmd.applyTo(m_program);
						done = true;
						break;
					}
				}
			}
			
			inst = inst.getPrevious();
			if (inst == null || inst.getFlowType().toString() != "FALL_THROUGH") 
				break;
		}
		return done;
	}
	
	private void updateEquatesByHash(String name, long value, long hash, Address refAddr) {
		EquateTable et = m_program.getEquateTable();
		Equate equate = null;
		try {
			equate = et.createEquate(name, value);
			
		} catch (DuplicateNameException e) {
			equate = et.getEquate(name);
		} catch (InvalidInputException e) {
			return;
		}
		equate.addReference(hash, refAddr);
	}
	
	private void runDecompilerAnalysis(Program program, Collection<Function> functions,
			TaskMonitor monitor) throws InterruptedException, Exception {

		DecompileConfigurer configurer = decompiler -> setupDecompiler(program, decompiler);

		DecompilerCallback<Void> callback = new DecompilerCallback<Void>(program, configurer) {

			@Override
			public Void process(DecompileResults results, TaskMonitor m) throws Exception {
				inspectFunction(program, results, monitor);
				return null;
			}
		};

		try {
			ParallelDecompiler.decompileFunctions(callback, functions, monitor);
		}
		finally {
			callback.dispose();
		}
	}
		
	private void inspectCallStatement(ClangNode call) {
		Address callPos = null;
		String funcName = null;
		
		// find func name and call pos
		int funcNameIdx = 0;
		for(; funcNameIdx < call.numChildren(); funcNameIdx++) {
			if(call.Child(funcNameIdx) instanceof ClangFuncNameToken)
			{
				funcName = call.Child(funcNameIdx).toString();
				callPos = call.Child(funcNameIdx).getMinAddress();
				break;
			}
		}
		if(funcName == null)
			return;
		
		
		if(!m_database.contains(funcName))
			return;
		System.out.println("[Ghidra Win32 A] Analyzing " + funcName + " call at" + callPos);
		

		int paramCount = 0;
		int paramCountMax = m_database.getNumParameter(funcName);
		for(int i = funcNameIdx+1; i < call.numChildren() && paramCount < paramCountMax; i++) {
			ClangNode param = call.Child(i);
			if(param instanceof ClangVariableToken) {
				paramCount++;
				
				// check is constant
				Varnode convertVn = ((ClangVariableToken) param).getVarnode();
				if (convertVn == null || !convertVn.isConstant()) 
					continue;
				
				// check equate exist
				HighSymbol symbol = convertVn.getHigh().getSymbol();
				EquateSymbol convertSymbol = null;
				if (symbol != null) {
					if (symbol instanceof EquateSymbol) {
						convertSymbol = (EquateSymbol) symbol;
						int type = convertSymbol.getConvert();
						if (type == EquateSymbol.FORMAT_DEFAULT) {
							continue;
						}
					}
					else {
						continue;		// Something already attached to constant
					}
				}
				
				// check is number
				DataType convertDataType = convertVn.getHigh().getDataType();
				boolean convertIsSigned = false;
				if (convertDataType instanceof AbstractIntegerDataType) {
					if (convertDataType instanceof BooleanDataType) {
						continue;
					}
					convertIsSigned = ((AbstractIntegerDataType) convertDataType).isSigned();
				}
				else if (convertDataType instanceof Enum) {
					continue;
				}
				
				// check if replacement exist
				long value = convertVn.getOffset();
				String constants = getConstants(funcName, paramCount-1, value);
				if(constants == null || constants.isBlank())
					continue;
				
				PcodeOp op = convertVn.getLoneDescend();
				Address convertAddr = op.getSeqnum().getTarget();
				DynamicHash dynamicHash = new DynamicHash(convertVn, 0);
				long convertHash = dynamicHash.getHash();
				
				if(!updateEquates(callPos, constants, value)) // try fin const in listing
					updateEquatesByHash(constants, value, convertHash, convertAddr);
				
				System.out.println("[Ghidra Win32 A] Applied Equate \"" + constants + "\" for " + funcName + " call at " + call.getMinAddress());

			}
		}
	}

	private void inspectFunction(Program program, DecompileResults results, TaskMonitor monitor) {
		// For debug only
		
		LinkedList<ClangNode> q = new LinkedList<>();
		q.add(results.getCCodeMarkup());
		while(!q.isEmpty()) {
			ClangNode tok = q.getFirst();q.removeFirst();
			if(tok instanceof ClangFuncNameToken && !(tok.Parent() instanceof ClangFuncProto)) {
				inspectCallStatement(tok.Parent());
			}
			
			if(tok.numChildren() > 0) {
				for(int i = 0; i < tok.numChildren(); i++) {
					q.addLast(tok.Child(i));
				}
			}
		}

	}

	private void setupDecompiler(Program p, DecompInterface decompiler) {
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(p);
		options.setEliminateUnreachable(false);
		decompiler.setOptions(options);
	}
}
