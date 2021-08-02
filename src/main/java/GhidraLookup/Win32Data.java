package GhidraLookup;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import org.json.*;

import ghidra.framework.Application;

public class Win32Data {
	
	// a possible constant used in a function parameter
	public class Constant {
		public String name;
		public Integer value;
		
		Constant(String _name, Integer _value) {
			name = _name;
			value = _value;
		}
	}
	
	private class Parameter {
		String name;
		String type;
		String description;
		ArrayList<Constant> possible_constants; // ArrayList<Pair<String, Integer>> doesn't work
		
		Parameter(String _name, String _type, String _des) {
			possible_constants = new ArrayList<Constant>();
			name = _name;
			type = _type;
			description = _des;
		}
		
		public void addPC(String pc_name, Integer pc_value) {
			Constant pc = new Constant(pc_name, pc_value);
			possible_constants.add(pc);
		}
	}
	
	// a Win32 API function
	private class Function {
		String name;
		String return_type;
		String msdn;
		String description;
		ArrayList<Parameter> parameters;
		
		Function(String _name, String _return_type, String _msdn, String _description) {
			parameters = new ArrayList<Parameter>();
			name = _name;
			return_type = _return_type;
			msdn = _msdn;
			description = _description;
		}
		
		public void addParameter(Parameter p) {
			parameters.add(p);
		}
	}
	
	private HashMap<String, Function> m_functions;
	
	public Win32Data() {
		
		m_functions = new HashMap<String, Function>();
		
		String root_dir = Application.getMyModuleRootDirectory().getAbsolutePath();
		
		loadData(root_dir + "/data/winuser.json");
		loadData(root_dir + "/data/shellapi.json");
		loadData(root_dir + "/data/heapapi.json");
		loadData(root_dir + "/data/processthreadsapi.json");
	}
	
	private void loadData(String file_name) {
		Path file = Paths.get(file_name);
		byte[] fileArray = null;
		try {
		    fileArray = Files.readAllBytes(file);
		} catch (IOException e) {
		    // TODO Auto-generated catch block
		    e.printStackTrace();
		}
		String raw = new String(fileArray);
		JSONObject object = new JSONObject(raw);
		JSONArray functions = object.getJSONArray("functions");
		for(Iterator<Object> it = functions.iterator(); it.hasNext();) {
		    JSONObject func = (JSONObject)it.next();
		    String name = func.getString("name");
		    String return_type = func.getString("return_type");
		    String msdn = func.getString("msdn");
		    String description = func.getString("description");
		    
		    Function f = new Function(name, return_type, msdn, description);
		    JSONArray pars = func.getJSONArray("parameters");
		    
		    for(Iterator<Object> par_it = pars.iterator(); par_it.hasNext();) {
		    	JSONObject par = (JSONObject)par_it.next();
		    	String par_name = par.getString("name");
		    	String par_type = par.getString("type");
		    	String par_des = par.getString("description");
		    	Parameter p = new Parameter(par_name, par_type, par_des);
		    	
		    	// load possible constants
		    	JSONArray pcs = par.getJSONArray("possible_constants");
		    	for(int i = 0; i < pcs.length(); i++) {
		    		String constant_name = pcs.getJSONArray(i).getString(0); 
		    		Integer constant_value = pcs.getJSONArray(i).getInt(1);
		    		p.addPC(constant_name, constant_value);
		    	}

		    	
		    	f.addParameter(p);
		    }
		    m_functions.put(f.name, f);
		}
		System.out.println("[Ghidra Win32Data] Loaded json file: " + file);
	}
	
	public ArrayList<String> getFunctionList() {
		ArrayList<String> all_funcs = new ArrayList<>();
		for(Function f : m_functions.values()) {
			all_funcs.add(f.name);
		}
		return all_funcs;
	}
	
	public ArrayList<String> getFunctionList(String prefix) {
		prefix = prefix.toLowerCase();
		ArrayList<String> all_funcs = new ArrayList<>();
		for(Function f : m_functions.values()) {
			String name = f.name.toLowerCase();
			if(name.startsWith(prefix))
				all_funcs.add(f.name);
		}
		return all_funcs;
	}
	
	public Boolean contains(String func_name) {
		return m_functions.containsKey(func_name);
	}
	
	public String getDescription(String func_name) {
		if(!contains(func_name))
			return null;
		return m_functions.get(func_name).description;
	}
	
	public String getURL(String func_name) {
		if(!contains(func_name))
			return null;
		return m_functions.get(func_name).msdn;
	}
	
	public String getReturnType(String func_name) {
		if(!contains(func_name)) 
			return null;
		return m_functions.get(func_name).return_type;
	}
	
	public int getNumParameter(String func_name) {
		if(!contains(func_name)) 
			return 0;
		return m_functions.get(func_name).parameters.size();
	}
	
	public String getNthParameterName(String func_name, int index) {
		if(!contains(func_name))
			return null;
		
		if(index < 0 || getNumParameter(func_name) <= index)
			return null;
		
		return m_functions.get(func_name).parameters.get(index).name;
	}
	
	public String getParameterType(String func_name, int param_index) {
		if(!contains(func_name))
			return null;
		
		if(param_index < 0 || getNumParameter(func_name) <= param_index)
			return null;
		
		return m_functions.get(func_name).parameters.get(param_index).type;
	}
	
	public String getParameterType(String func_name, String param_name) {
		if(!contains(func_name))
			return null;
		
		for(Parameter param : m_functions.get(func_name).parameters) {
			if(param.name == param_name)
				return param.type;
		}
		
		return null;
		
	}
	
	public ArrayList<String> getParameters(String func_name) {
		if(!contains(func_name))
			return null;
		
		ArrayList<Parameter> pars = m_functions.get(func_name).parameters;
		ArrayList<String> list = new ArrayList<String>();
		
		for(int i = 0; i < pars.size(); i++) {
			list.add(pars.get(i).name);
		}
		
		return list;
	}
	
	public String getParameterDescription(String func_name, String par_name) {
		if(!contains(func_name))
			return null;
		ArrayList<Parameter> pars = m_functions.get(func_name).parameters;
		for(int i = 0; i < pars.size(); i++) {
			if(pars.get(i).name.equals(par_name))
				return pars.get(i).description;
		}
		return null;
	}
	
	public ArrayList<Constant> getParameterReplacements(String func_name, String par_name) {
		if(!contains(func_name))
			return null;
		
		ArrayList<Parameter> pars = m_functions.get(func_name).parameters;
		for(int i = 0; i < pars.size(); i++) {
			if(pars.get(i).name.equals(par_name)) {
				return pars.get(i).possible_constants;
			}
		}
		return null;
	}
}
