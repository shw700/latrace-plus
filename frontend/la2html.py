#!/usr/bin/python

import sys
import re


def get_indent(line):
	count = 0

	for i in line:
		if i != ' ':
			break
		count += 1

	return count

def emit_html_header():
	h = "<html>"
	h += "<head>"
	h += "<title>latrace output</title>"
	h += '<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>'
	h += "<script>"
	h += "$(document).ready(function(){"
	h += '$("#toggle_tid").click(function(){'
	h += '		console.log("Toggling TID display");'
	h += '		$(".label_tid").not("#toggle_tid").not(".toggle_button").toggle();'
	h += "});"
	h += '$("#toggle_src_lib").click(function(){'
	h += '		console.log("Toggling source library display");'
	h += '		$(".label_src_lib").not("#toggle_src_lib").toggle();'
	h += "});"
	h += '$("#toggle_dst_lib").click(function(){'
	h += '		console.log("Toggling dest library display");'
	h += '		$(".label_dst_lib").not("#toggle_dst_lib").toggle();'
	h += "});"
	h += '$(".label_expander").click(function(){'
	h += '		console.log("Toggling expansion");'
	h += '		$(this).parent().parent().children(".func_call").not($(this)).slideToggle();'
	h += "});"
	h += '$(".label_src_lib").not("#toggle_src_lib").click(function(){'
	h += '		console.log("Hiding references to source library");'
	h += '		var selector = ".label_src_lib[xlib=\'\" + $(this).attr("xlib") + \"\']";'
	h += '		console.log("SELECTOR: " + selector);'
	h += '		$(selector).not("#toggle_src_lib").parent().parent().toggle();'
	h += '		$(selector).removeClass("enabled").addClass("disabled");'
	h += "});"
	h += '$(".label_funcname").dblclick(function(){'
	h += '		console.log("Hiding references to function name: " + $(this).attr("xfunc"));'
	h += '		var selector = ".label_funcname[xfunc=\'\" + $(this).attr("xfunc") + \"\']";'
	h += '		console.log("SELECTOR: " + selector);'
	h += '		$(selector).not(".toggle_func").parent().parent().slideToggle();'
	h += '		if ($(selector).hasClass("enabled"))'
	h += '			$(selector).removeClass("enabled").addClass("disabled");'
	h += '		else'
	h += '			$(selector).removeClass("disabled").addClass("enabled");'
	h += "});"
	h += '$(".toggle_tid").dblclick(function(){'
	h += '		console.log("Hiding TID contents for: " + $(this).attr("xtid"));'
	h += '		var selector = ".label_tid[xtid=\'\" + $(this).attr("xtid") + \"\']";'
	h += '		console.log("SELECTOR: " + selector);'
	h += '		$(selector).not(".toggle_button").parent().parent().find(".func_call").toggle();'
	h += '		$(this).removeClass("enabled").addClass("disabled");'
	h += "});"
	h += '$("#toggle_all_funcs").dblclick(function(){'
	h += '		console.log("Toggling all visible functions");'
	h += '		$(".func_call").toggle();'
	h += '		if ($(this).hasClass("enabled")) {'
	h += '			$(".toggle_func").removeClass("enabled").addClass("disabled");'
	h += '			$(this).removeClass("enabled").addClass("disabled");'
	h += '		} else {'
	h += '			$(".toggle_func").removeClass("disabled").addClass("enabled");'
	h += '			$(this).removeClass("disabled").addClass("enabled");'
	h += '		}'
	h += "});"
	h += "});"
	h += "</script>"
	h += "<style>"
	h += ".func_call { padding-left: 2px; padding-top: 5px; padding-bottom: 5px; margin-bottom: 5px; border: 1px dotted black; border-left: 1px dotted black; border-right: none; margin-bottom: 0px; margin-top: 5px; }"
	h += ".label_src_lib { display: inline-block; cursor: hand; background-color: orange; border: 1px solid black; padding: 3px; font-size: 75%; float: right; }"
	h += ".label_dst_lib { display: inline-block; cursor: hand; background-color: brown; border: 1px solid black; padding: 3px; font-size: 75% }"
	h += ".label_tid { display: inline-block; cursor: hand; background-color: yellow; border: 1px solid black; padding: 3px; font-size: 75%; }"
	h += ".label_funcname { display: inline-block; cursor: hand; font-weight: bold; border: 1px dotted silver; padding: 3px; padding: 3px; }"
	h += ".label_fparams { display: inline-block; background-color: silver; padding: 1px; }"
	h += ".label_remainder { display: inline-block; color: gray; }"
	h += ".label_result { display: inline-block; background-color: red; border: 1px solid black; padding-left: 10px; padding-right: 10px; margin-left: 5px; font-weight: bold; font-size: 125%; float: right; margin-right: 50px; }"
	h += ".label_expander { display: inline-block; cursor: hand; background-color: gray; border: 1px solid black; padding: 3px; margin-left: 5px; margin-right: 2px; font-weight: bold; font-size: 75%; }"
	h += ".label_console { display: inline-block; background-color: black; color: white; padding: 5px; width: 100%; padding-top: 5px; padding-bottom: 5px; }"
	h += ".side_bar { display: inline-block; margin-right: 10px; width: 150px; }"
	h += ".func_bar { display: inline-block; margin-right: 10px; width: 50%; }"
	h += ".func_indent { display: inline-block; background-color: silver; margin-right: 2px; }"
	h += ".toggle_button { display: inline-block; cursor: hand; margin-left: 3px; margin-right: 3px; margin-bottom: 2px; padding: 3px; }"
	h += ".toggle_func { margin-left: 2px; margin-right: 2px; margin-bottom: 2px; }"
	h += ".enabled { background-color: lime; }"
	h += ".disabled { background-color: red; }"
	h += "</style>"
	h += "</head>"
	h += "<body>"
	return h

def emit_html_footer():
	h = "</body>"
	h += "</html>"
	return h

if len(sys.argv) != 2:
	sys.stderr.write("Error: requires an input file\n");
	sys.exit(-1)

lines = open(sys.argv[1], "r").read().splitlines()

user_struct_transformers = []
user_func_transformers = []
user_intercepts = []
all_functions = []
all_functions_map = {}
all_libraries = []
all_tids = []

# borrowed from stack exchange
ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')

line_no = 0
first_indent = next_indent = indent_inc = indent_level = 0
last_indent = 0
main_tid = 0
first = 1

header = emit_html_header()
body = ""

for line in lines:
	set_xfrm_func = set_xfrm_struct = set_u_int = False
#	body += "LINE: ", line
#	line = line.join([i if ord(i) >= ' ' else '' for i in line])
	line = ansi_escape.sub('', line).strip()

	if line.startswith("Adding user struct transformer function"):
		set_xfrm_struct = True
	elif line.startswith("Adding user transformer function for function"):
		set_xfrm_func = True
	elif line.startswith("Adding user intercept function"):
		set_u_int = True

	if set_xfrm_func or set_xfrm_struct or set_u_int:
		pind = str.find(line, ":")

		if pind == -1:
			continue

		param = line[pind+1:].strip()

		if param.endswith("()"):
			param = param[:-2]

		if set_xfrm_func:
			user_func_transformers.append(param)
		elif set_xfrm_struct:
			user_struct_transformers.append(param)
		else:
			user_intercepts.append(param)

		continue

	words = line.split(" ")

	if len(words) < 2:
		continue

	try:
		tid = int(words[0])
	except:
		body += '<div class="label_console">{}</div><br>'.format(line)
		continue

	all_tids.append(tid)
	all_tids = sorted(set(all_tids))

	if (main_tid == 0):
		main_tid = tid

	line = " ".join(words[1:])

	if line_no == 0:
		first_indent = get_indent(line)
		
	line_no += 1
	indent = get_indent(line)

	if (first_indent > 0) and (next_indent == 0):
		if (indent > first_indent):
			next_indent = indent
			indent_inc = next_indent - first_indent

	if (indent_inc > 0):
		indent_level = (indent - first_indent) /indent_inc
	else:
		indent_level = 0

	line = line.strip()
	ltoks = str.split(line, '(')
	func_name = ltoks[0]
	func_params = "(".join(ltoks[1:])
	aftoks = str.split(func_params, ')')
	func_params = aftoks[0]
	remainder = ")".join(aftoks[1:])
	result = ""
	lib_name = ""

	ftoks = str.split(func_name, ":")
	if len(ftoks) == 2:
		lib_name = ftoks[0]
		func_name = ftoks[1]
	elif (len(ftoks) >= 2) and (func_name.find("[") != -1) and (func_name.find("]") != -1):
		lidx = func_name.find("[")
		ridx = func_name.find("]")
		remainder = func_name[lidx+1:ridx]
		lib_name = ftoks[0]
		func_name = func_name[func_name.find(":")+1:lidx-1]
	elif (len(ftoks) > 2) and (not ftoks[0].startswith("}")):
		lib_name = ftoks[0]
		func_name = ":".join(ftoks[1:])

	one_liner = False
	eqidx = remainder.find(" = ")
	if eqidx != -1:
		result = remainder[eqidx+3:]
		remainder = remainder[0:eqidx-1]
		one_liner = True

	if first:
		first = False
#	elif indent_level == last_indent:
#		body += "</div>"

	prefix, func_indent = "", ""
	i = 0

	while i < indent_level:
		prefix += "+"
		func_indent += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
		i += 1

	func_indent = '<div class="func_indent">{}</div>'.format(func_indent)

#	prefix += '<div class="label_expander"><b>+</b></div>'
	prefix = '<div class="label_expander"><b>{}+</b></div>'.format(indent_level)

	if result != "":
		result_str = "<b> </b><div class=\"label_result\">=&nbsp;&nbsp;&nbsp;{}</div>".format(result)
	else:
		result_str = "<br>"

	if remainder != "":
		remainder = remainder.strip()
		if remainder.startswith("["):
			remainder = remainder[1:]
		if remainder.find("]") != -1:
			remainder = remainder[:remainder.find("]")]

		remainder_str = '<div class="label_dst_lib" xlib="{}">{}</div>'.format(remainder, remainder)
	else:
		remainder_str = ""

	if lib_name == "":
		lib_name_str = ""
	else:
		lib_name_str = '<div class="label_src_lib" xlib="{}">{}</div>'.format(lib_name, lib_name)

	if lib_name == "" and func_name.startswith("}"):
		body += '<div class="side_bar"><div class="label_tid" xtid="{}">{}</div>      {}     </div>      <div class="label_result">RESULT of <b>{}</b></div><br>'.format(tid, tid, prefix, func_name[2:])
		body += "</div>"
	else:
		if func_name.startswith("["):
			func_name = func_name[1:]
		div_class = "div_ind_{}".format(indent_level)
		body += '<div class="{} func_call">'.format(div_class)
		body += '<div class="side_bar"><div class="label_tid" xtid="{}">{}</div>      {}{}     </div><div class="func_bar">{}<div class="label_funcname" xfunc="{}">{}</div>     (<div class="label_fparams">{}</div>)</div>     {}     {}'.format(tid, tid, prefix, lib_name_str, func_indent, func_name, func_name, func_params, remainder_str, result_str)
		all_functions.append(func_name)
		all_functions.sort()
		if (remainder != "") and (remainder.find(" ") == -1):
			all_functions_map[func_name] = remainder
			all_libraries.append(remainder)
			all_libraries.sort()

		if one_liner:
			body += "</div>"

	if indent_level < last_indent:
		body += "</div>"

	last_indent = indent_level



user_func_transformers.sort()
user_struct_transformers.sort()
user_intercepts.sort()

header += "<br><b>Loaded function transformers: {}</b><br>".format(len(user_func_transformers))
for f in user_func_transformers:
	header += '<div class="toggle_func label_funcname enabled" xfunc="{}">{}()</div>'.format(f, f)
header += "<br><br>"

header += "<b>Loaded struct transformers: {}</b><br>".format(len(user_struct_transformers))
header += "\t{}<br><br>".format(", ".join(user_struct_transformers))
header += "<b>Loaded function intercepts: {}</b><br>".format(len(user_intercepts))
for f in user_intercepts:
	header += '<div class="toggle_func label_funcname enabled" xfunc="{}">{}()</div>'.format(f, f)
header += "<br><br>"

all_functions = sorted(set(all_functions))
header += "<b>All called functions: {} unique</b><br>".format(len(all_functions))
header += '<div style="border: 1px solid black;" id="toggle_all_funcs" class="toggle_button toggle_func enabled">{}</div>'.format("Toggle all functions")
header += "<br><br>"
all_libraries = sorted(set(all_libraries))
header += "<b>In a total of {} libraries</b><br>".format(len(all_libraries))
for l in all_libraries:
	header += '<div style="float: none; font-size: 100%;" class="label_src_lib toggle_button" xlib="{}">{}</div>'.format(l, l)
header += "<br><br>"
functions_left = all_functions
#while len(functions_left) > 0:
for l in all_libraries:
	header += '<div style="display: inline-block; font-size: 100%; margin-right: 15px; " class="label_dst_lib toggle_button"><u>{}</u></div>'.format(l)
	for f in functions_left:
		if (f in all_functions_map) and (all_functions_map[f] == l):
			header += '<div class="toggle_func label_funcname enabled" xfunc="{}">{}()</div>'.format(f, f)
#			functions_left.remove(f)
	header += "<br><br>"
#for f in all_functions:
#	header += '<div class="toggle_func label_funcname enabled" xfunc="{}">{}()</div>'.format(f, f)
header += "<br><br>"

header += "<b>Available thread IDs: {}</b><br>".format(len(all_tids))
for t in all_tids:
	header += '<div class="label_tid toggle_tid toggle_button enabled" xtid="{}">{}</div>'.format(t, t)

header += "<br><br>"
header += "<br><br>"
header += '<div id="toggle_tid" class="label_tid toggle_button">{}</div>'.format("Display TIDS")
header += '<div style="float: none;" id="toggle_src_lib" class="label_src_lib toggle_button">{}</div>'.format("Display source lib names")
header += '<div id="toggle_dst_lib" class="label_dst_lib toggle_button">{}</div>'.format("Display dst lib names")
header += '<div style="padding: 1px; border: 1px solid black; cursor: hand;" id="toggle_fparams" class="label_fparams toggle_button">{}</div>'.format("Display function parameters")
header += "<br><br><br>"
		
#	header += '</div><div class="toggle_func label_funcname enabled" xfunc="{}">{}()</div>'.format(f, f)
#	header += "<br><br>"

print header
print body
print emit_html_footer()
