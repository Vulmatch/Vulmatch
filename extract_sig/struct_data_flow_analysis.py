from pdb import set_trace as bp
from string_util import delete_comments
import re

#Given an initial argument that we need to trace. We scan the c source code function line by line. We add the 
#variable to trace whenever there is an assignment. We record the line whenever the traced variable is used.
#Paramerer 0: a list of lines of the c source code.
#Parameter 1: a dictionary record each line corresponding to which function.
#Parameter 2: the arguments at the beginning of the function we need to trace.
#Parameter 3: the function we want to analyze.
def data_flow_main(lines,c_line_function,initial_taints,function,changed_structs): 
 function_range=extract_function_range(c_line_function,function)
 if function_range==None:
  bp()
 function_start_line=find_function_start(lines,function_range)
 variables=[]
 for var_name in initial_taints:
  variables.append(var_name)
 recorded_lines=[]
 #bp()
 for i in range(function_start_line,function_range[1]):
  #if "since the conn struct may have changed or been replaced." in lines[i]:#For debug purpose
  # bp()
  string=delete_comments(lines[i]).strip()
  if is_struct_declare_line(string):#Lines like: struct abc test;
    changed_struct_var_name=has_changed_struct(string,changed_structs)
    if changed_struct_var_name:
     variables.append(changed_struct_var_name)
  else:
   status=check_variable_status_in_this_line(string,variables)
   if status=="assign":
     new_variable=extract_assigned_variable(string)
     variables.append(new_variable)
     recorded_lines.append(i)
   elif status=="use":
     recorded_lines.append(i)
  
 return recorded_lines

def is_struct_declare_line(string):
 if re.match("struct[\s]+[a-zA-Z0-9_]+[\s]+[*]*[a-zA-Z0-9_\[\]]*[\s]*;",string):
  return True
 else:
  return False
 
def has_changed_struct(string,changed_structs):
 tokens=string.split(" ")
 var_name=None
 if tokens[1] in changed_structs:
  var_name=string.split(tokens[1])[1]
  if var_name.startswith("*"):
   var_name=var_name[1:]
  var_name.replace(";","")
  var_name=var_name.strip()
 return var_name
 
#Delete the comment within the line.
def trim_comment(string):
 if "/*" in string:
  return string.split("/*")[0]
 elif "//" in string:
  return string.split("//")[0]
 else:
  return string

#Checks the line string has one of the tainted variables.
def has_tainted_variable(variables,line_string):
 for variable in variables:
   tainted_variable_index=line_string.find(variable)
   if tainted_variable_index!=-1 and (not line_string[tainted_variable_index-1].isalpha()) and (not line_string[tainted_variable_index-1].isdigit()) and (line_string[tainted_variable_index-1]!='_') and (not line_string[tainted_variable_index+len(variable)].isalpha()) and (not line_string[tainted_variable_index+len(variable)].isdigit()) and (line_string[tainted_variable_index+len(variable)]!='_'):#line has tainted variable
    return tainted_variable_index
 return -1

#Check whether this line assigns the tainted variable to new variable, or this line just uses the 
#tainted variable, or this line has nothing to do with the variables.
#Parameter 0: a line string
#Parameter 1: a list recording all tainted variables
def check_variable_status_in_this_line(line_string,variables):
 #if "struct FTP *pop3 = data->state.proto.pop3;" in string:
 #  bp()
 #line_string=trim_comment(string)
 equation_index=line_string.find("=")
 double_equation_index=line_string.find("==")
 tainted_variable_index=has_tainted_variable(variables,line_string)
 if equation_index!=-1 and double_equation_index==-1:#line has '=' symbol
   if tainted_variable_index!=-1:#line has tainted variable
    if tainted_variable_index>equation_index: #line is assignment of tainted variable
      print("assign!",line_string)
      return 'assign'
    else:#May be reassignment of the tainted value?
     print("use!",line_string)
     return 'use'
   else:#Nothing to do with tainted varaible
     return 'none'
 elif double_equation_index==-1 and tainted_variable_index!=-1 :#A use of the tainted variable
   print("use!",line_string)
   return 'use'
 elif double_equation_index!=-1:#line has '==' symbol
   if tainted_variable_index!=-1:#has tainted variable
    print("use!",line_string)
    return 'use'
   else:#Doesn't have tainted variable
    return 'none'
 else:
   return 'none'

#Extract the newly assigned variable
def extract_assigned_variable(string):
  #line_string=trim_comment(string)
  left=string.split("=")[0]
  assigned_variable=left.strip().split(" ")[-1]
  assigned_variable.replace("*","")
  return assigned_variable

#Find all the lines belonging to function.
def extract_function_range(c_line_function,function):
 lines=[]
 for i in c_line_function:
  if c_line_function[i]==function:
   lines.append(i)
 if len(lines)==0:
   return None
 return (lines[0],lines[-1])

#Find the first line of '{' symbol.
def find_function_start(lines,function_range):
 for line_index in range(function_range[0],function_range[1]):
  line_string=trim_comment(lines[line_index])
  if '{' in line_string:
   return line_index
  
def test():
   from pattern import listize_lines
   c_file=input("Please enter the .c file to be processed:").strip("'")
   initiate_taint=input("Please enter the tainted argument:").strip("'")
   function=input("Please enter the function name:").strip("'")
   
   f=open(c_file,'r')
   lines=f.read().split('\n')
   c_line_function=listize_lines(c_file)
   tainted_line=data_flow_main(lines,c_line_function,initiate_taint,function)
   for line in tainted_line:
    print(line,": ",lines[int(line)]) 

#test()
