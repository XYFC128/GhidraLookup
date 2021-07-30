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

import static java.nio.file.StandardOpenOption.*;
import java.nio.file.*;
import java.util.Iterator;
import java.io.*;

import org.json.*;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ghidra_win32Analyzer extends AbstractAnalyzer {

	public ghidra_win32Analyzer() {

		// TODO: Name the analyzer and give it a description.
		super("Win32 API Analyzer", "Analyze Win32 functions", AnalyzerType.BYTE_ANALYZER);
		Win32Data data = new Win32Data();
		System.out.println(data.getDescription("MessageBoxA"));

	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		System.out.println("[Ghidra Win32 A] Binary Foramat: " + program.getExecutableFormat());
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// options.registerOption("Option name goes here", false, null, "Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
	    
		System.out.println("[Ghidra Win32 A] Starting Analysis...");
		
		FunctionManager fm = program.getFunctionManager();
		for(FunctionIterator fi = fm.getExternalFunctions(); fi.hasNext();) {
			Function func = fi.next();
			String lib = func.getExternalLocation().getLibraryName();
			System.out.println("[Ghidra Win32 A] Function: " + func.getName() + " in " + lib);
		}
		
		System.out.println("[Ghidra Win32 A] Analysis Compelete");
		
		return true;
	}

}
