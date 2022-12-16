from pdb import set_trace as bp
from string_util import *
c_key_word=["if","else","while","for"]
MAX_MULTIPLE_LINE=30

#Assume we extracted the within brackets content, we need to check whether it ends with ';'. If yes, that is a declaration.
#mode 0 denotes the function line cross multiple lines. 1 means it is in a single line.
def is_function_declaration(lines,line_index,mode):
 if mode==1:#function is in a single line
  string=delete_comments(lines[line_index])
  if string.strip().endswith(';'):
   return True
   
 elif mode==0:
  function_name=extract_complete_function_name(lines,line_index)
  if function_name_check(function_name)==False:
    return False
  return function_line_semi_colon(line_index+1,lines)
     

#Start from start_line to find the first line that has the balanced ')' symbol.
def function_line_semi_colon(start_line,lines):
 level=1
 
 window_string=""
 if start_line+MAX_MULTIPLE_LINE>len(lines):
  end=len(lines)
 else:
  end= start_line+MAX_MULTIPLE_LINE
 for line_index in range(start_line,end):
  window_string+=lines[line_index]
 string=delete_comments(window_string)
 after_string=""#record the string after func()
 for char_index in range(0,len(string)):
  if string[char_index]=='(':
   level+=1
  elif string[char_index]==')':
   level-=1
  if level==0:
    after_string=string[char_index+1:]
    break
 after_string=after_string.strip()
 if after_string.startswith(';'):
  return True
 return False
 
#Given a extracted function name string, check its validity to be a function name.
def function_name_check(function_name):
 if ("=" in function_name or "return" in function_name  or "(" in function_name  or "+" in function_name or "-" in function_name or '|' in function_name or '[' in function_name or ']' in function_name or ":" in function_name or "__asm__ volatile" in function_name):
   return False
 if ' ' not in function_name:#If it is like func(), it is not a function definition.
    return False
 return True

  

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

#Input is a c file, we extract all functions names and their line ranges as a dictionary and return. In this version, we use a more simpler method to extract each function line range. WE directly detect whether line is function define, and lines in between of two func defined are ranges.
def analyze_single_c_file_simple(c_path):
 print("c path is:",c_path)
 line_function_name={}#A dictionary reverse the key-value of the above dictionary
 f=open(c_path,'r',encoding = "ISO-8859-1")
 content=delete_comments(f.read())
 lines=content.split("\n")
 f_name=""
 line_index=0
 while line_index <len(lines):
  #print("line_index:",line_index)
  #print(lines[line_index])
  #start_line=0#Record each function start
  #end_line=0#Record each function end
  #bp()
  #if "return schannel_connect_common(conn, sockindex, TRUE, done);" in lines[line_index]:
  # bp()
  #if "CVE-2015-3145" in c_path: 
  # if "Curl_cookie_add(struct SessionHandle *data," in lines[line_index]:
  #  bp()
  if is_classic_function_define(lines,line_index)==True:
    name=extract_fname(lines[line_index])
    #print(name)
    #bp()
    if name in c_key_word:
     if f_name!="":
      line_function_name[line_index]=f_name
     line_index+=1
     continue
    elif name=='':
     line_index+=1
     continue
    else:#Really identify a function define
     f_name=name
     line_function_name[line_index]=f_name
     #end_line=line_index-1
     #line_range=(start_line,end_line)
     #for i in range(line_range[0],line_range[1]+1):#fill line function dictionary
      
      #print(i,f_name)
     #start_line=line_index
  elif line_index==  len(lines)-1:#Reach EOF:
   #end_line=line_index
   #line_range=(start_line,end_line)
   #for i in range(line_range[0],line_range[1]+1):#fill line function dictionary
   line_function_name[line_index]=f_name
  else: 
    if f_name!="":
     line_function_name[line_index]=f_name
  line_index+=1
 #print(line_function_name)
 #if "CVE-2016-9952" in c_path: 
 # bp()
 return line_function_name

def listize_lines(c_path):
 print("c path is:",c_path)
 line_function_name={}#A dictionary reverse the key-value of the above dictionary
 f=open(c_path,'r',encoding = "ISO-8859-1")
 content=f.read()
 lines=content.split("\n")
 comment_lines=record_comments(lines)
 f_name=""
 line_index=0
 while line_index <len(lines):
  if line_index in comment_lines:
   #line_function_name[line_index]=f_name
   line_index+=1
   continue
  #if line_index==92 and "pngrutil.c" in c_path:
  # bp()
  #print("line_index:",line_index)
  #print(lines[line_index])
  #start_line=0#Record each function start
  #end_line=0#Record each function end
  #bp()
  #if "return schannel_connect_common(conn, sockindex, TRUE, done);" in lines[line_index]:
  # bp()
  #if "CVE-2015-3145" in c_path: 
  #if 'static int  __attribute__((noinline))rsa_builtin_keygen(RSA *rsa, int bits, BIGNUM *e_value,' in lines[line_index]:
  #  bp()
  if is_classic_function_define(lines,line_index,comment_lines)==True:
    name=extract_fname(lines[line_index])
    if name=='||':
     bp()
    #print(name)
    #bp()
    if name in c_key_word:
     if f_name!="":
      line_function_name[line_index]=f_name
     line_index+=1
     continue
    elif name=='':
     line_index+=1
     continue
    elif ("ffserver.c" in c_path and line_index==1615) or ("cavsdsp.c" in c_path ) or ("h264.c" in c_path and line_index==2184) or ("ffserver.c" in c_path and "CVE-2016-10192" in c_path and line_index==1574) or ("dsputil.c" in c_path and "CVE-2013-7010" in c_path and ((line_index>=801 and line_index<=1322) or line_index==2409 or line_index==2443 or line_index==2485)  ):
     line_index+=1
     continue
    else:#Really identify a function define
     f_name=name
    line_range=extract_line_range(lines,line_index,comment_lines)
    if line_range==None:
     return{}
    #function_name_line_range[f_name]=line_range
    for i in range(line_range[0],line_range[1]+1):
     line_function_name[i]=f_name
     #line_function_name[line_index]=f_name
     #end_line=line_index-1
     #line_range=(start_line,end_line)
     #for i in range(line_range[0],line_range[1]+1):#fill line function dictionary
      
      #print(i,f_name)
     #start_line=line_index
  elif line_index==  len(lines)-1:#Reach EOF:
   #end_line=line_index
   #line_range=(start_line,end_line)
   #for i in range(line_range[0],line_range[1]+1):#fill line function dictionary
   line_function_name[line_index]=f_name
  '''else: 
    if f_name!="":
     line_function_name[line_index]=f_name'''
  line_index+=1
 #print(line_function_name)
 #if "CVE-2016-9952" in c_path: 
 # bp()
 return line_function_name


#Input is a c file and all modified (vulnerable) functions. We need to add no-inline to all these functions.
def modify_single_c_file(c_path,funcs):
 print("c path is:",c_path)
 #if "tiffcp.c" in c_path and "tiffcp" in funcs:
 #  bp()
 f=open(c_path,'r',encoding = "ISO-8859-1")
 #content=delete_comments(f.read())
 content=f.read()
 lines=content.split("\n")
 comment_lines=record_comments(lines)
 f.close()
 f_name=""
 line_index=0
 while line_index <len(lines):
  #print("line_index:",line_index)
  #print(lines[line_index])
  #if line_index==3809:
  # bp()
  #start_line=0#Record each function start
  #end_line=0#Record each function end
  #bp()
  #if "png_inflate(png_structp png_ptr, const png_byte *data, png_size_t size," in lines[line_index]:
  # bp()
  if line_index in comment_lines:
    line_index+=1
    continue
  #if "tiff-4.0.7/tools/tiffcp.c " in c_path and line_index==593: 
  #if "ikev2_e_print(netdissect_options *ndo," == lines[line_index]:
  #  bp()
  if "__attribute__((noinline))" in lines[line_index]:
   line_index+=1
   continue
   
  elif is_classic_function_define(lines,line_index)==True:
    name=extract_fname(lines[line_index])
    #print(name)
    #bp()
    if name in c_key_word:
     line_index+=1
     continue
    elif name=='':
     line_index+=1
     continue
    else:#Really identify a function define
     f_name=name
     if f_name in funcs:
      lines[line_index]=add_no_inline(f_name,lines[line_index])
      print("Modified:")
      print(lines[line_index-1])
      print(lines[line_index])
      print(lines[line_index+1])
  line_index+=1
 
 #if "CVE-2016-9952" in c_path: 
 # bp()
 new_string=""
 for line in lines:
  new_string+=line+"\n"
 f=open(c_path,"w")
 f.write(new_string)
 f.close()
 
def add_no_inline(f_name,line_string):
 f_name_start=line_string.find(f_name)
 new_string=line_string[:f_name_start]+" __attribute__((noinline))"+line_string[f_name_start:]
 return new_string

#Check whether the string has unbalanced '('. If has, return the level unbalanced.
def unbalanced_check(symbol,line_string):
  level=0
  if symbol=='(' or symbol==')':
   left='('
   right=')'
  for i in line_string:
   if i==left:
    level+=1
   elif i==right:
    level-=1
  return level
    
#Given a flattened function parameters string(i.e., (int a, \n int b) turn to (int a, int b)), we check whether it is function parameters string. Return True if it is function definition. False otherwise
def check_function_parameters(within_bracket):
  if ',' not in within_bracket:#If within the bracket there is only one parameter
   element=within_bracket.strip()
   if element=="void":
     return True
   elif ' ' not in element:
     return False
   elif '-' in element or '.' in element or '+' in element or '>' in element or '<' in element or '=' in element or '"' in element or "'" in element:
     return False
   else:
     #print(line_string,"is function definetion!")
     return True
  elif ',' in within_bracket:#If within the bracket there has more than two parameters
   #within_bracket=within_bracket.replace("\n","")
   elements=within_bracket.strip().split(",")
   elements = list(filter(None, elements))
   for element in elements:
    element=element.strip()
    if element=='...':
     continue
    if ' ' not in element:
     return False
    elif '-' in element or '.' in element or '+' in element or '>' in element or '<' in element or '=' in element or '"' in element or "'" in element:
     return False
   return True 

#If the function definition is like (int a \n int n \n int c), we need to cross multiple lines to make the parameters all together, and delete \n
def extract_within_brackets(lines,start_line):
 level=1
 
 window_string=""
 if start_line+MAX_MULTIPLE_LINE>len(lines):
  end=len(lines)
 else:
  end=start_line+MAX_MULTIPLE_LINE
 for line_index in range(start_line,end):
  window_string+=lines[line_index]
 string=delete_comments(window_string)
 for char_index in range(0,len(string)):
  if string[char_index]=='(':
   level+=1
  elif string[char_index]==')':
   level-=1
  if level==0:
    return string[:char_index]


#Currently we only decide it is a function call if it is in the form of: xxx (xx xx, xx xx,...)
def is_classic_function_define(lines,line_index,comment_line_record=[]):
 line_string=trim_comment(lines[line_index])
 #if line_index==96:
 #  bp()
 if '(' in line_string and unbalanced_check('(',line_string)==1:#Line is like func(
  if is_function_declaration(lines,line_index,0):#In case of function name declaration
   return False
  #Firstly we check function name format
  function_name=extract_complete_function_name(lines,line_index,comment_line_record)
  '''if "=" in function_name or "return" in function_name or "(" in function_name  or "+" in function_name or "-" in function_name or '|' in function_name or '[' in function_name or ']' in function_name:#A use of a function
   return False
  elif ' ' not in function_name:#If it is like func(), it is not a function definition.
   return False'''
  if function_name_check(function_name)==False:
   return False
  within_bracket=line_string.split("(")[-1]#Next we check function parameter format
  if extract_within_brackets(lines,line_index+1)==None:
   bp()
  within_bracket+=extract_within_brackets(lines,line_index+1)

  #if ')' in within_bracket and within_bracket.count(')')==1:#in case ')' is in the same line
  # within_bracket=within_bracket.split(")")[0]
  result=check_function_parameters(within_bracket)
  return result
 elif '(' in line_string and unbalanced_check('(',line_string)==0:#Line is like func(int a, int b)
  if is_function_declaration(lines,line_index,1):#In case of function name declaration
   return False
  #Firstly we check function name format
  function_name=extract_complete_function_name(lines,line_index,comment_line_record)
  '''if "=" in function_name or "return" in function_name or "(" in function_name or "+" in function_name or "-" in function_name or '|' in function_name or '[' in function_name or ']' in function_name:#A use of a function
   return False
  elif ' ' not in function_name:#If it is like func(), it is not a function definition.
   return False'''
  if function_name_check(function_name)==False:
   return False
  #Next we check function parameter format
  within_bracket=line_string.split('(')[-1].split(')')[0]
  result=check_function_parameters(within_bracket)
  return result
 else:
  return False

#Extract the function start and end lines
def extract_line_range(lines,initial_line,comment_lines):
 #if initial_line==364:
 # bp()
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
 left_side_if_macro=0#record how many macro ifdef on the left side. If !=0, means we are in the macro def.
 #if start_line==953 or start_line==1421:
 # bp()
 back_slash=0#Record whether we are in a back-slash-leading character.
 line_string=delete_comments(lines[start_line])
 if type(start_char)!=int:
  bp()
 for char_index in range(0,len(line_string[start_char:])):#Scan the first line of function
  if back_slash==1:#If currently we are at a back-slash-leading character, ignore current cahracter.
    back_slash=0
    continue
  elif line_string[start_char:][char_index]=='{' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    level+=1
  elif line_string[start_char:][char_index]=='}' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    level-=1
  elif line_string[start_char:][char_index] == '"' and left_side_one_quotation%2==0:
    left_side_quotation+=1
  elif line_string[start_char:][char_index]=="'" and left_side_quotation%2==0:
    left_side_one_quotation+=1
  elif line_string[start_char:][char_index]=="\\":
    back_slash=1
 #if start_line==5036:
 # bp()
 for line_index in range(start_line+1,len(lines)):#Scan the rest of the lines
  #print(line_index,"/",len(lines),lines[line_index])
  #if line_index==263:
  # bp()
  if line_index in comment_lines:#If whole line is comment
   continue
  line_string=delete_comments(lines[line_index])
  for char_index in range(0,len(line_string)):
   if back_slash==1:#If currently we are at a back-slash-leading character, ignore current cahracter.
    back_slash=0
    continue
   elif line_string[char_index]=='{' and left_side_quotation%2==0 and left_side_one_quotation%2==0 and left_side_if_macro==0:
    level+=1
    #print(lines[line_index],"level+, level=",level,line_index)
   elif line_string[char_index]=='}' and left_side_quotation%2==0 and left_side_one_quotation%2==0 and left_side_if_macro==0:
    level-=1
    #print(lines[line_index],"level-, level=",level,line_index)
   elif line_string[char_index]=='"' and left_side_one_quotation%2==0:
    left_side_quotation+=1
   elif line_string[char_index]=="'" and left_side_quotation%2==0:
    left_side_one_quotation+=1
    #print(lines[line_index],"left_side_one_quotation=",left_side_one_quotation)
   elif line_string[char_index]=="#":
    if line_string[char_index+1:char_index+3]=="if":
     left_side_if_macro+=1
    elif line_string[char_index+1:char_index+6]=="endif":
     left_side_if_macro-=1
   elif line_string[char_index]=="\\":
    back_slash=1
   if level==0:
    return (initial_line,line_index)
   #if left_side_quotation%2==1 and line_index>249:
   # bp()
 print("can not get function end, function start line:",lines[start_line-1])
 print(lines[start_line],"start line:",start_line,"initial_line:",initial_line)
 #bp()
 line_index=input("I can't identify function end, please help me:")
 return (initial_line,int(line_index)-1)

