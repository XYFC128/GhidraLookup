#/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import json

domain = "https://docs.microsoft.com"

paths = {
	"shellapi" : "/en-us/windows/win32/api/shellapi/",
	"winuser"  : "/en-us/windows/win32/api/winuser/",
}

data = {
	"functions" : [
	]
}

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
		else:
			func_data["return_type"] = "" # found in syntax

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
		func_data["parameters"] = []
		i = tmp.find_next_sibling("p")
		# a parameter is defined in 3 paragraphs
		while i and i.find("code"):
			param_data = {}
			p_name = i.text.strip()
			print("  param name: {}".format(p_name))
			param_data["name"] = p_name
			i = i.find_next_sibling("p")
			if i and i.text.startswith("Type:"):  # sometimes the 2nd paragraph is the type
				p_type = i.text.replace("Type: ", "").strip()
				print("  param type: {}".format(p_type))
				param_data["type"] = p_type
				i = i.find_next_sibling("p")
			# parse parameter description
			p_desc = i.text.strip()
			print("  param desc: {}\n".format(p_desc))
			param_data["description"] = p_desc
			func_data["parameters"].append(param_data)
			i = i.find_next_sibling("p")
		data["functions"].append(func_data)
	except AttributeError:
		function_limit = 0
		print("[!] Function Fetch Failed")
		return

def main():
	# tests
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createsyntheticpointerdevice', "CreateSyntheticPointerDevice")
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa', 'MessageBoxA')
	# fetch_function('https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-wvsprintfa', 'wvsprintfA')
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