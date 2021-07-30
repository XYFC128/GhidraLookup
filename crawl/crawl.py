#/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from bs4 import element
import json

domain = "https://docs.microsoft.com"

paths = {
	"shellapi" : "/en-us/windows/win32/api/shellapi/",
	"winuser"  : "/en-us/windows/win32/api/winuser/",
	"heapapi"  : "/en-us/windows/win32/api/heapapi/",
	"processthreadsapi" : "/en-us/windows/win32/api/processthreadsapi/" 
}

data = {
	"functions" : [
	]
}

def sibling_tag(i):
	i = i.next_sibling
	while i and not isinstance(i, element.Tag):
		i = i.next_sibling
	return i

def sibling_p(i):
	while i.name != "p":
		i = sibling_tag(i)
	return i

def request_site(site):
	req = requests.get(site)
	if req.status_code != 200:
		print("failed to fetch {}".format(site))
	print("[*] requested {}:".format(site))
	return BeautifulSoup(req.text, 'html.parser')

function_limit = 99990 # limit functions

def fetch_function(site, f_name):
	global function_limit
	if function_limit == 0:
		return
	function_limit -= 1

	func_data = {
    	"name" : f_name,
        "return_type" : "",
        "msdn" : site,
        "description" : "",
        "parameters" : []
    }

	try:
		soup = request_site(site)
		m = soup.find("main", {"id":"main"})

		print("function name: {}".format(f_name))
		func_data["name"] = f_name

		# parse syntax
		i = m.find("h2", {"id":"syntax"}).find_next_sibling("pre")
		print("function syntax: {}".format(i.text))

		# parse return value
		i = m.find("h2", {"id":"return-value"}).find_next_sibling("p")
		if i and i.text.startswith("Type:"): # sometimes the first paragraph is not the type
			f_ret_type = i.text.replace("Type: ", "").strip()
			print("function return value: {}".format(f_ret_type))
			func_data["return_type"] = f_ret_type

		# parse function description
		i = m.find("h1").find_next_sibling("p")
		f_desc = i.text.strip()
		print("function description: {}".format(f_desc))
		func_data["description"] = f_desc

		# parse function parameters
		tmp = m.find("h2", {"id":"parameters"})
		if not tmp:  # function has no parameters
			data["functions"].append(func_data)
			return
		i = tmp.find_next_sibling("p")
		while i and i.find("code"):
			param_data = {
				"name" : "",
				"type" : "",
				"description" : "",
				"possible_constants" : [] 
			}
			p_name = i.text.strip()
			print("  param name: {}".format(p_name))
			param_data["name"] = p_name
			i = sibling_tag(i)
			if i and i.name == "p" and i.text.startswith("Type:"):  # sometimes the 2nd paragraph is the type
				p_type = i.text.replace("Type: ", "").strip()
				print("  param type: {}".format(p_type))
				param_data["type"] = p_type
				i = sibling_tag(i)
			# parse parameter description and their possible constants
			p_desc = ""
			p_constants = ""
			while i and (i.name == "p" or i.name == "table") and not i.find("code"):
				if i.name == "p":  # append description
					p_desc += "\n" + i.text.strip()
				elif i.name == "table" and i.tr.th.text.startswith("Value"):  # append possible constants
					constants = i.find_all("tr")[1:]
					for constant in constants:
						dt = constant.td.find_all("dt")
						if not dt: # no value for this constant
							c_name = constant.td.text
							c_value = -1
						elif len(dt) == 1:
							c_name = dt[0].text
							c_value = -1
						elif len(dt) == 2: # no value for this constant
							c_name = dt[0].text
							c_value = int(dt[1].text.replace("L", "").replace("U", ""), 16) if dt[1].text.startswith("0x") else -1
						print("{} : {}".format(c_name, c_value))
						param_data["possible_constants"].append([c_name, c_value])
				i = sibling_tag(i)

			print("  param desc: {}\n".format(p_desc))
			param_data["description"] = p_desc
			func_data["parameters"].append(param_data)
		data["functions"].append(func_data)
	except AttributeError:
		function_limit = 0
		print("[!] Function Fetch Failed")
		return

def main():
	# test fetches
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createsyntheticpointerdevice', "CreateSyntheticPointerDevice")
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa', 'MessageBoxA')
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-wvsprintfa', 'wvsprintfA')
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-changedisplaysettingsa', 'ChangeDisplaySettingsA')
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-deferwindowpos', 'DeferWindowPos')
	# with open("./data/test.json", "w") as f:
	# 	f.write(json.dumps(data))
	# return
	for file, path in paths.items():
		soup = request_site(domain + path)
		m = soup.find("main", {"id":"main"})
		headers = m.find_all("h2")
		tables = m.find_all("table")
		assert(len(headers) == len(tables))
		for header, table in zip(headers, tables):
			# fetch function attributes
			if header.text.lower() == "functions":
				for a in table.find_all("a"):
					fetch_function(domain + a['href'], a.text)

		with open("./data/" + file + ".json", "w") as f:
			f.write(json.dumps(data))

if __name__ == '__main__':
	main()