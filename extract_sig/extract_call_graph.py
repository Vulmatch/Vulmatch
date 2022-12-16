from pdb import set_trace as bp
import pandas as pd
import os
c_key_word=["if","else","while","for"]
all_cve_root='/home/nuc/Downloads/vulnerable_binaries/curl'

#SOmetimes the function name can split into several lines. We need to extract the complete name.
def extract_complete_function_name(lines,line_index):
 function_name=lines[line_index].split("(")[0].strip()#current line
 for i in range(line_index-1,0,-1):
  prev_line=lines[i].strip() 
  if len(prev_line)>0:
   if prev_line[-1] in [";","}","&","|","+","-","*","/","%","!"]:
    break
   else:
    function_name=prev_line+function_name
  else:
   function_name=prev_line+function_name
 return function_name

def is_function_declaration(lines,line_index):
 if lines[line_index].count("(")!=1:#Indecator of a use of the function
  return False
 #function_name=lines[line_index].split("(")[0].strip()#FIrstly we check function name format
 function_name=extract_complete_function_name(lines,line_index)
 #if 'msnprintf' in function_name:
 # bp()
 if "=" in function_name:
  return False
 if ' ' not in function_name:#If it is like func(), it is not a function definition.
   return False

 right_bracket=0
 for line in lines[line_index:]:
  if ")" in line:
   if ";" in line:
    return True
   else:
    return False
  

#Currently we only decide it is a function call if it is in the form of: xxx (xx xx, xx xx,...)
def is_classic_function_define(lines,line_index):
 line_string=lines[line_index]
 if '(' in line_string and line_string.count('(')==1:
  if is_function_declaration(lines,line_index):#In case of function name declaration
   return False
  #function_name=line_string.split("(")[0].strip()#Firstly we check function name format
  function_name=extract_complete_function_name(lines,line_index)
  if "=" in function_name:#A use of a function
   return False
  elif ' ' not in function_name:#If it is like func(), it is not a function definition.
   return False
  within_bracket=line_string.split("(")[-1]#Next we check function parameter format
  if ')' in within_bracket and within_bracket.count(')')==1:#in case ')' is in the same line
   within_bracket=within_bracket.split(")")[0]
  if ',' not in within_bracket:#If within the bracket there is only one parameter
   element=within_bracket.strip()
   if ' ' not in element:
     return False
   else:
     #print(line_string,"is function definetion!")
     return True
  elif ',' in within_bracket:#If within the bracket there has more than two parameters
   within_bracket=within_bracket.replace("\n","")
   elements=within_bracket.split(",")
   elements = list(filter(None, elements))
   for element in elements:
    element=element.strip()
    if element=='...':
     continue
    if ' ' not in element:
     return False
   #print(line_string,"is function definetion!")
   return True
 else:
  return False

#Given a starting line, we find the first line with a '{' which denotes the start of the function. We also find the index of that '{'
def find_start_line_start_char(lines,line_index):
 left_side_quotation=0#record how many quotations " on the left side. If odd, means we are in the quotation, then the '{' we encounter does not count.
 left_side_one_quotation=0#record how many quotations ' on the left side. If odd, means we are in the quotation, then the '{' we encounter does not count.

 for index in range(line_index,len(lines)):
  for char_index in range(0,len(lines[index])):
   if lines[index][char_index]=='{' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    return index,char_index+1
   elif lines[index][char_index]=='"' and left_side_one_quotation%2==0 and not_string_quote(lines[index],char_index):
    left_side_quotation+=1
   elif lines[index][char_index]=="'" and left_side_quotation%2==0 and not_string_quote(lines[index],char_index):
    left_side_one_quotation+=1
 raise("Can not find the start line and start character!") 

#Ensure the " or ' is not the content within the string but the real symbol of string.
def not_string_quote(string,char_index):
 if string[char_index] not in ["'",'"']:
  return False
 elif string[char_index-1]=='\\' and string[char_index] in ["'",'"']:
  if string[char_index-2]!='\\':
   return False
  elif string[char_index-2]=='\\':
   return True
 else:
  return True
  

#extract 'xxxx' out of 'xxxx ('
def extract_fname(line_string):
 left_bracket=line_string.find('(')
 name=line_string[:left_bracket].split(" ")[-1].strip()
 return name

#Extract the function start and end lines
def extract_line_range(lines,initial_line):
 start_line=0
 start_char=0
 left_braket=lines[initial_line].find('{')
 if left_braket!=-1:
  start_line=initial_line
  start_char=left_braket+1
 else:
   start_line,start_char=find_start_line_start_char(lines,initial_line)
   #print("start_line=",start_line,"start_char=",start_char)
 to_be_inspect=[]#The scop in the c file to be found the starting and end line of the function.
 to_be_inspect.append(lines[start_line][start_char:])
 for i in range(start_line+1,len(lines)):
  to_be_inspect.append(i)
 level=1
 #print("lines[start_line][start_char:]:",lines[start_line][start_char:])
 left_side_quotation=0#record how many quotations " on the left side. If odd, means we are in the quotation, then the '{' we encounter does not count.
 left_side_one_quotation=0#record how many quotations ' on the left side. If odd, means we are in the quotation, then the '{' we encounter does not count.
 #if start_line==953 or start_line==1421:
 # bp()
 for char_index in lines[start_line][start_char:]:#Scan the first line of function
  if lines[start_line][start_char:][char_index]=='{' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    level+=1
  elif lines[start_line][start_char:][char_index]=='}' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    level-=1
  elif lines[start_line][start_char:][char_index] == '"' and left_side_one_quotation%2==0 and not_string_quote(lines[start_line][start_char:],char_index):
    left_side_quotation+=1
  elif lines[start_line][start_char:][char_index]=="'" and left_side_quotation%2==0 and not_string_quote(lines[start_line][start_char:],char_index):
    left_side_one_quotation+=1
 for line_index in range(start_line+1,len(lines)):#Scan the rest of the lines
  #print(line_index,"/",len(lines),lines[line_index])
  #if line_index==288:
  # bp()
  for char_index in range(0,len(lines[line_index])):
   if lines[line_index][char_index]=='{' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    level+=1
    #print(lines[line_index],"level+, level=",level,line_index)
    
   elif lines[line_index][char_index]=='}' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    level-=1
    #print(lines[line_index],"level-, level=",level,line_index)
    
   elif lines[line_index][char_index]=='"' and left_side_one_quotation%2==0 and not_string_quote(lines[line_index],char_index):
    left_side_quotation+=1
   elif lines[line_index][char_index]=="'" and left_side_quotation%2==0 and not_string_quote(lines[line_index],char_index):
    left_side_one_quotation+=1
    #print(lines[line_index],"left_side_one_quotation=",left_side_one_quotation)
   if level==0:
    return (initial_line,line_index)
 print("can not get function end, function start line:",lines[start_line-1],lines[start_line],start_line)

#Input is a c file, we extract all functions names and their line ranges as a dictionary and return.
def analyze_single_c_file(c_path):
 print("c path is:",c_path)
 #function_name_line_range={}#A dixtionary recording each function and their line ranges
 line_function_name={}#A dictionary reverse the key-value of the above dictionary
 f=open(c_path,'r',encoding = "ISO-8859-1")
 content=delete_comments(f.read())
 lines=content.split("\n")
 #print(lines)
 #bp()
 for line_index in range(0,len(lines)):
  #print("line_index:",line_index)
  #if line_index==3809:
  # bp()
  if is_classic_function_define(lines,line_index)==True:
    f_name=extract_fname(lines[line_index])
    if f_name in c_key_word or f_name=='':
     continue
    #if f_name=="'":
    # bp()
    #print("function name:",f_name,"len(lines)",len(lines))
    line_range=extract_line_range(lines,line_index)
    if line_range==None:
     return{}
    #function_name_line_range[f_name]=line_range
    for i in range(line_range[0],line_range[1]+1):
     line_function_name[i]=f_name
     #print(i,f_name)
 return line_function_name

#Given a function name, we find all its caller, caller's caller, and etc. in case this f_name is inlined in one of the callers.
def find_callers(f_name,line_function_name,lines,level):
 if level==5:
  return []
 result=[]
 for line_index in range(0,len(lines)):
  if (f_name+"(" in lines[line_index] or f_name+" (" in lines[line_index]):
   #if line_index==492:
   #bp()
   if is_function_declaration(lines,line_index):
    continue
   if line_index not in line_function_name:#line not in dict, might be because meet itself or because some error we didn't read that line and function in the dictionary.
    continue
   if line_function_name[line_index]==f_name:#Meet it self
    continue
   caller_function=line_function_name[line_index]
   grand_pa_caller=find_callers(caller_function,line_function_name,lines,level+1)
   #print(caller_function,level)
   result.append((caller_function,level+1))
   for f_name1 in grand_pa_caller:
    result.append(f_name1)
 result = list(dict.fromkeys(result))
 return result
 
#input is the content read from a .c file. We need to delete all the comments. 
def delete_comments(long_string):
 char_index=0
 left_quotation=0
 left_single_quotation=0
 while char_index < len(long_string):
  if long_string[char_index]=='"' and left_single_quotation%2==0 and not_string_quote(long_string,char_index):
   left_quotation+=1
  elif long_string[char_index]=="'" and left_quotation%2==0 and not_string_quote(long_string,char_index):
   left_single_quotation+=1
  elif long_string[char_index:char_index+2]=='/*' and left_single_quotation%2==0 and left_quotation%2==0:
   tail= long_string.find("*/",char_index+2)
   long_string=long_string[:char_index]+long_string[tail+2:]
  elif long_string[char_index:char_index+2]=='//' and left_single_quotation%2==0 and left_quotation%2==0:
   tail=long_string.find("\n",char_index+2)
   long_string=long_string[:char_index]+long_string[tail+1:]
  char_index+=1
 return long_string

#Divide each .c file and function name by cve index.
def read_xml(xml_path, sheet_name):
  cve_dict={}
  df=pd.read_excel(xml_path, sheet_name)
  cve_index=list(filter(None, df["CVE"]))
  file_path=list(filter(None, df["File Path"]))
  func_name=list(filter(None, df["Function Name"]))
  key=""
  for cve,f,names in zip(cve_index,file_path,func_name):
   #if cve=="CVE-2009-0037":
   # bp()
   #print(cve)
   if str(f)=="nan" or str(names)=="nan":#If we encounter lines have not enough information, skip it.
    continue
   if str(cve)!='nan':
    key=cve
    cve_dict[key]=[]
   all_name=str(names).split(",")
   funcs=[]
   for i in all_name:#Each .c file can have multiple updated functions
    if i != "nan":#WE dont append null if this line of record has only .c file with 0 function
     funcs.append(i)
   #print(key,f,funcs)
   cve_dict[key].append((f,funcs))#Each cve can have multiple updated .c files
  #for cve in cve_dict:
  # print(cve,cve_dict[cve])
  #bp()
  return cve_dict

#Find under all_cve_root/cve_index, all the paths contatining c_file in filename
def find_c_path(cve_index,c_file_name):
  print(cve_index,"c_file_name:",c_file_name)
  c_file=c_file_name.split("/")[-1]
  c_paths=[]
  cve_path=all_cve_root+"/"+str(cve_index)
  versions=os.listdir(cve_path)
  for version in versions:
   version_path=cve_path+"/"+version
   files=os.listdir(version_path)
   for each_file in files:
    if each_file==c_file:
     c_paths.append(version_path+"/"+each_file)
  #print("c_paths:",c_paths)
  return c_paths
  

def main():
 #c_path=input("Please enter the c file:")
 #line_function_name=analyze_single_c_file(c_path)
 #print(line_function_name)

 xml_path=input("Please enter the cve.xml path:").strip("'")
 sheet_name=input("Please enter the sheet name:")
 cve_dict=read_xml(xml_path, sheet_name)
 
 #f=open(c_path,'r')
 #content=delete_comments(f.read())
 #lines=content.split("\n")
 
 #result=find_callers(function,line_function_name,lines,0)
 #print(result)
 reachable_cve=os.listdir(all_cve_root)
 count=0
 all_records=0
 for i in cve_dict:
  all_records+=len(cve_dict[i])
 for cve in cve_dict:
  if cve=="CVE-2020-8169":
   bp()
  if cve not in reachable_cve:#For cve we can not reimplement and thus no corresponding file, just skip.
   print("No such file:",cve,"skip it...")
   continue
  for file_funcs in cve_dict[cve]:#For each .c file in the cve
   #if str(file_funcs[1])=="nan":#Have .c file but no vulnerable function record, skip it.
   # continue
   c_paths=find_c_path(cve,file_funcs[0])#contains two versions .c file paths
   for c_path in c_paths:
    version_path=c_path.split(".c")[0]
    funcs_call_result=""
    line_function_name=analyze_single_c_file(c_path)
    if line_function_name=={}:
      print("analyze",c_paths,"failed!")
      call_chain_path=version_path+"_call_chain.txt"
      f=open(call_chain_path,"w")#If failed, still create a txt file for later manual fill out the file.
    
      for func in file_funcs[1]:
       funcs_call_result+=func+": [('', 1)]\n"
      f.write(funcs_call_result)
      f.close()
      continue
    f=open(c_path,'r',encoding = "ISO-8859-1")
    content=delete_comments(f.read())
    lines=content.split("\n")
    f.close() 
    call_chain_path=version_path+"_call_chain.txt"
    f=open(call_chain_path,"w")
    for func in file_funcs[1]:#For each updated function in .c file
     func_call_result=str(func)+": "
     #print("cve_dict[cve][1]:",cve_dict[cve][1])
     func_call_result+=str(find_callers(func,line_function_name,lines,0))
     func_call_result+="\n"
     print(func_call_result)
     funcs_call_result+=func_call_result
   
    
    #f=open(call_chain_path,"w")
    f.write(str(funcs_call_result))
    f.close()
    count+=1
    print("finished",count,"out of",all_records)

def process_single_c_file():
 c_path=input("Please enter the c file:").strip("'")
 line_function_name=analyze_single_c_file(c_path)
 print(line_function_name)
 f=open(c_path,'r')
 content=delete_comments(f.read())
 lines=content.split("\n")
 function=str(input("Please enter the function name:"))
 #print(line_function_name)
 result=find_callers(function,line_function_name,lines,0)
 print(result)

main()
#process_single_c_file()
