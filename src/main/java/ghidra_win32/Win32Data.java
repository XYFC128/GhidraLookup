package ghidra_win32;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import org.json.*;

public class Win32Data {
	
	private class Parameter {
		String name;
		String type;
		String description;
		ArrayList<String> possible_constants;
		
		Parameter(String _name, String _type, String _des) {
			possible_constants = new ArrayList<String>();
			name = _name;
			type = _type;
			description = _des;
		}
		
		public void addPC(String pc_name) {
			possible_constants.add(pc_name);
		}
	}
	
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
		
		loadData();
	}
	
	private void loadData() {
		Path file = Paths.get("./data/winuser.json");
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
		    	
		    	JSONArray pcs = par.getJSONArray("possible_constants");
		    	for(int i = 0; i < pcs.length(); i++) {
		    		p.addPC(pcs.getString(i));
		    	}
		    	
		    	f.addParameter(p);
		    }
		    m_functions.put(f.name, f);
		}
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
	
	public int getNumParameter(String func_name, int index) {
		if(!contains(func_name)) 
			return 0;
		return m_functions.get(func_name).parameters.size();
	}
	
	public String getNthParameter(String func_name, int index) {
		if(!contains(func_name))
			return null;
		
		if(index < 1 || getNumParameter(func_name, index) < index)
			return null;
		
		return m_functions.get(func_name).parameters.get(index-1).name;
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
			if(pars.get(i).name == par_name)
				return pars.get(i).description;
		}
		return null;
	}
	
	public ArrayList<String> getParameterReplacements(String func_name, String par_name) {
		if(!contains(func_name))
			return null;
		
		ArrayList<String> replacements = new ArrayList<>();
		
		ArrayList<Parameter> pars = m_functions.get(func_name).parameters;
		for(int i = 0; i < pars.size(); i++) {
			if(pars.get(i).name == par_name) {
				for(int j = 0; j < pars.get(i).possible_constants.size(); i++) {
					replacements.add(pars.get(i).possible_constants.get(j));
				}
			}
		}
		return replacements;
	}
}
