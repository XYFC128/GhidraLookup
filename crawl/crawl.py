#/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from bs4 import element
import json

domain = "https://docs.microsoft.com"

# update this list and run this script to update .json files
paths = {
	"shellapi" :          "/en-us/windows/win32/api/shellapi/",
	"winuser"  :          "/en-us/windows/win32/api/winuser/",
	"heapapi"  :          "/en-us/windows/win32/api/heapapi/",
	"processthreadsapi" : "/en-us/windows/win32/api/processthreadsapi/" 
}

data = {
	"functions" : [
	]
}

def hex_to_int(s):
	assert(s.startswith("0x"))
	return int(s.replace("U", "").replace("L", ""), 16)

def get_suffix_num(s):
	i = len(s) - 1
	while s[i] in '0123456789':
		i -= 1
	return s[i+1:] if i < len(s) - 1 else ""

# as BeautifulSoup does not provide this functionality, we implement this ourselves
def sibling_tag(i):
	i = i.next_sibling
	while i and not isinstance(i, element.Tag):
		i = i.next_sibling
	return i if isinstance(i, element.Tag) else None

def request_site(site):
	req = requests.get(site)
	if req.status_code != 200:
		print("failed to fetch {}".format(site))
	print("[*] requested {}:".format(site))
	return BeautifulSoup(req.text, 'html.parser')

# function fetch limit
function_limit = 99990

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
		# <p><code>param name</code></p>
		while i and i.find("code"): # found new parameter name
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
			found_param_type = False
			# <p>Type: <b>param type</b></p>
			if i and i.name == "p" and i.text.startswith("Type:"):  # sometimes the 2nd paragraph is the type
				found_param_type = True
				p_type = i.text.replace("Type: ", "").strip()
				print("  param type: {}".format(p_type))
				param_data["type"] = p_type
				i = sibling_tag(i)
			# parse parameter description and their possible constants
			p_desc = ""
			p_constants = ""
			if found_param_type: # then the following paragraph must be its description
				p_desc += "\n" + i.text.strip()
				i = sibling_tag(i)
			while i and (i.name == "p" or i.name == "table") and not i.find("code"):
				if i.name == "p":  # append description
					p_desc += "\n" + i.text.strip()
				elif i.name == "table" and i.tr.th.text.startswith("Value"):  # append possible constants
					rows = i.find_all("tr")[1:]
					for row in rows:
						td = row.find_all("td", recursive=False)
						dt = row.td.find_all("dt")
						# <td><strong>name</strong><br>value</td><td>desc</td>
						if row.td.strong:
							c_name = td[0].strong.text
							c_value = int(get_suffix_num(td[0].text))
						elif not dt:
							c_name = row.td.text
							c_value = -1
						elif len(dt) == 1:
							c_name = dt[0].text
							c_value = -1
						# <td><dl><dt><b>name</b></dt>value<dt></dt></dl></td><td>desc</td>
						elif len(dt) == 2:
							c_name = dt[0].text
							c_value = hex_to_int(dt[1].text) if dt[1].text.startswith("0x") else -1
						print("    {} : {}".format(c_name, c_value))
						param_data["possible_constants"].append([c_name, c_value])
				i = sibling_tag(i)
			print("  param desc: {}\n".format(p_desc.strip()))
			param_data["description"] = p_desc.strip()
			func_data["parameters"].append(param_data)
		data["functions"].append(func_data)
	except AttributeError:
		function_limit = 0
		print("[!] Function Fetch Failed")
		return

# this script is meant to be run from the root directory:
#   python3 ./crawl/crawl.py
def main():
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