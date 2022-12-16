from pdb import set_trace as bp

#Check whether the string contain any one in the list 'keys'
def string_has(string,keys):
  for i in keys:
   if i in string:
    return True
  return False

#SOmetimes the function name can split into several lines. We need to extract the complete name.
def extract_complete_function_name(lines,line_index,comment_line_record=[]):
 line_string=trim_comment(lines[line_index])
 function_name=line_string[:lines[line_index].rfind('(')].strip()#current line
 #if lines[line_index]=="png_crc_read(png_structp png_ptr, png_bytep buf, png_size_t length)":
 # bp()
 for i in range(line_index-1,0,-1):
  if i in comment_line_record or lines[i].startswith("#"):#Encounter comment line or macro definition
   break
  prev_line=trim_comment(lines[i].strip()) 
  if len(prev_line)>0:
   if string_has(prev_line,[";","}","&","|","+","-","/","%","!","=",","]):#Don't have * since it has two meanings, mutiplier or pointer.
    break
   else:
    if prev_line[-1]!=" ":#If last line not end with ' '
     function_name=prev_line+" "+function_name
    else:#If last line ends with ' '
     function_name=prev_line+function_name
  else:
   function_name=prev_line+function_name
 function_name=function_name.replace('__attribute__((noinline))','')
 function_name=function_name.replace("\n"," ")
 return function_name

#Given a starting line, we find the first line with a '{' which denotes the start of the function. We also find the index of that '{'
def find_start_line_start_char(lines,line_index):
 left_side_quotation=0#record how many quotations " on the left side. If odd, means we are in the quotation, then the '{' we encounter does not count.
 left_side_one_quotation=0#record how many quotations ' on the left side. If odd, means we are in the quotation, then the '{' we encounter does not count.
 back_slash=0#Record whether we are in a back-slash-leading character.
 for index in range(line_index,len(lines)):
  line_string=delete_comments(lines[index])
  for char_index in range(0,len(line_string)):
   if back_slash==1:#If currently we are at a back-slash-leading character, ignore current cahracter.
    back_slash=0
    continue
   elif line_string[char_index]=='{' and left_side_quotation%2==0 and left_side_one_quotation%2==0:
    return index,char_index+1
   elif line_string[char_index]=='"' and left_side_one_quotation%2==0:
    left_side_quotation+=1
   elif line_string[char_index]=="'" and left_side_quotation%2==0:
    left_side_one_quotation+=1
   elif line_string[char_index]=="\\":
    back_slash=1
 bp()
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
  
#Delete the comment within the line.
def trim_comment(string):
 '''if "/*" in string:
  return string.split("/*")[0]
 elif "//" in string:
  return string.split("//")[0]
 else:
  return string'''
 char_index=0
 left_quotation=0
 left_single_quotation=0
 back_slash=0#Record whether we are in a back-slash-leading character.
 while char_index < len(string):
  if back_slash==1:#If currently we are at a back-slash-leading character, ignore current cahracter.
    back_slash=0
    continue
  elif string[char_index]=='"' and left_single_quotation%2==0:
   left_quotation+=1
  elif string[char_index]=="'" and left_quotation%2==0:
   left_single_quotation+=1
  elif string[char_index:char_index+2]=='/*' and left_single_quotation%2==0 and left_quotation%2==0:
   tail= string.find("*/",char_index+2)
   if tail!=-1:
    string=string[:char_index]+string[tail+2:]
   else:#If not find enclosing '*/' symbol, regard all the content after /* as comment
    string=string[:char_index]
  elif string[char_index:char_index+2]=='//' and left_single_quotation%2==0 and left_quotation%2==0:
   tail=string.find("\n",char_index+2)
   if tail!=-1:
    string=string[:char_index]+string[tail+1:]
   else:#If not find enclosing \n symbol, regard all the content after // as comment
    string=string[:char_index]
  elif string[char_index]=="\\":
    back_slash=1
  char_index+=1
 return string

#extract 'xxxx' out of 'xxxx ('
def extract_fname(line_string):
 line_string=trim_comment(line_string)
 left_bracket=line_string.rfind('(')
 if line_string[left_bracket-1]==" ":#If there is space between ( and name
  elements = line_string[:left_bracket].split(" ")
  elements = list(filter(None, elements))
  if len(elements)==0:
   name=""
  else:
   name=elements[-1].strip()
 else:#No space between ( and name
  name=line_string[:left_bracket].split(" ")[-1].strip()
 if name.startswith("*"):
  name=name.split("*")[-1]
 name=name.replace('__attribute__((noinline))','')
 name=name.replace("\n"," ")
 return name

#input is the content read from a .c file. We need to delete all the comments. 
def delete_comments(long_string):
 char_index=0
 left_quotation=0
 left_single_quotation=0
 back_slash=0#Record whether we are in a back-slash-leading character.
 while char_index < len(long_string):
  if back_slash==1:#If currently we are at a back-slash-leading character, ignore current cahracter.
    back_slash=0
    continue
  elif long_string[char_index]=='"' and left_single_quotation%2==0:
   left_quotation+=1
  elif long_string[char_index]=="'" and left_quotation%2==0:
   left_single_quotation+=1
  elif long_string[char_index:char_index+2]=='/*' and left_single_quotation%2==0 and left_quotation%2==0:
   tail= long_string.find("*/",char_index+2)
   if tail!=-1:
    long_string=long_string[:char_index]+long_string[tail+2:]
   else:#If not find enclosing '*/' symbol, regard all the content after /* as comment
    long_string=long_string[:char_index]
  elif long_string[char_index:char_index+2]=='//' and left_single_quotation%2==0 and left_quotation%2==0:
   tail=long_string.find("\n",char_index+2)
   if tail!=-1:
    long_string=long_string[:char_index]+long_string[tail+1:]
   else:#If not find enclosing \n symbol, regard all the content after // as comment
    long_string=long_string[:char_index]
  elif long_string[char_index]=="\\":
    back_slash=1
  char_index+=1
 return long_string

#input is the content read from a .c file. We need to delete all the comments. 
#We only record those lines are totally comments. When there are instruction before comment, it is not recorded.
def record_comments(string_list):
 comment_lines_list=[]
 line_index=0
 
 while line_index in range(0,len(string_list)):
   if string_list[line_index].strip().startswith('/*'):#Start with a multi-line comment
    comment_end_line=find_end_comment(line_index,string_list)
    if comment_end_line==None:
     bp()
    for line in range(line_index,comment_end_line+1):
     comment_lines_list.append(line)
    line_index=comment_end_line+1
    continue
   elif string_list[line_index].strip().startswith('//'):#Start with a single-line comment
    comment_lines_list.append(line_index)
   elif string_list[line_index].strip().find('/*')!=-1:#Multi-line comment is within the line
    comment_end_line=find_end_comment(line_index,string_list)
    if comment_end_line==None:
     bp()
    for line in range(line_index+1,comment_end_line+1):
     comment_lines_list.append(line)
    line_index=comment_end_line+1
    continue
   line_index+=1
    
 return comment_lines_list

def record_macro_if(string_list):
  macro_if_lines=[]
  left_side_if_macro=0
  #In some c file, the unbalanced #if might start at the beginning of the file. Thus we first find the first function define line and start there.
  last_include_index=-1
  for line_index in range(0,len(string_list)):
   if string_list[line_index].startswith("#include"):
    last_include_index=line_index

  '''#The last "#include" can also in a #if and #endif section. Thus we consider this situation.
  for line_index in range(last_include_index,len(string_list)):
   line_string=delete_comments(string_list[line_index])
   if "#if" in line_string:
    start_index=last_include_index
    break
   elif "#endif" in line_string:
    start_index=line_index+1
    break'''
  
  for line_index in range(last_include_index,len(string_list)):
   
   line_string=delete_comments(string_list[line_index])
   for char_index in range(0,len(line_string)):
     if line_string[char_index]=="#":
      if line_string[char_index+1:char_index+3]=="if":
       left_side_if_macro+=1
      elif line_string[char_index+1:char_index+6]=="endif":
       left_side_if_macro-=1
   if left_side_if_macro!=0:
    macro_if_lines.append(line_index)
   elif left_side_if_macro==0 and line_string.find("endif")!=-1:
    macro_if_lines.append(line_index)
   #if line_index==3098:
   #  bp()
   #if left_side_if_macro==-1:
   # bp()
  return macro_if_lines 

#We use an alternative method to compute the macro if lines. Firstly, we find each #if and its corresponding #endif. Next we filter out some super big #if "endif pairs which contains all the functions. As a result, all the remaining pairs which contains 0 to total function number-1 functions, are considered really macro lines. 
def record_macro_if_1(string_list,start_line,start_char,recorded_comment_line):
 debug_start_line=start_line
 macro_lines=[]
 line_string=delete_comments(string_list[start_line])
 while start_line < len(string_list):
  line_has_new_if=False
  #For the first line, start from start_index
  if start_line not in recorded_comment_line:
   for char_index in range(start_char,len(line_string)):
    if line_string[char_index]=="#":
        if line_string[char_index+1:char_index+3]=="if": 
           #bp()
           tmp_start_line,tmp_start_char,tmp_macro_lines=record_macro_if_1(string_list,start_line,char_index+3,recorded_comment_line)
           macro_lines.append((start_index,tmp_start_line))
           start_line=tmp_start_line
           start_char=tmp_start_char
           for ranges in  tmp_macro_lines:
             macro_lines.append(ranges)
           line_has_new_if=True
           break
        elif line_string[char_index+1:char_index+6]=="endif":
           #bp()
           return start_line,char_index+6,macro_lines
  if line_has_new_if:
   continue
  #For rest of the lines
  for line_index in range(start_line+1,len(string_list)):
   if line_index in recorded_comment_line:
    continue
   line_string=delete_comments(string_list[line_index])
   for char_index in range(0,len(line_string)):
     if line_string[char_index]=="#":
       if line_string[char_index+1:char_index+3]=="if":
        #bp()
        tmp_start_line,tmp_start_char,tmp_macro_lines=record_macro_if_1(string_list,line_index,char_index+3,recorded_comment_line)
        macro_lines.append((line_index,tmp_start_line))
        #if debug_start_line==2205:
        # print(line_index,tmp_start_line)
        # bp()
        start_line=tmp_start_line
        start_char=tmp_start_char
        for ranges in  tmp_macro_lines:
          macro_lines.append(ranges)
        line_has_new_if=True
        break
       elif line_string[char_index+1:char_index+6]=="endif":
        #bp()
        return line_index,char_index+6,macro_lines
   if line_has_new_if:#If found a new #if and #endif, scan for next #if and #endif
    break
  if line_has_new_if:#If found a new #if and #endif, scan for next #if and #endif
   continue
  else:
   start_line+=1
 return None,None,macro_lines 

#Find the first */ denoting the end of comment
def find_end_comment(start_line,string_list):
 for line in range(start_line,len(string_list)):
  if '*/' in string_list[line]:
   return line
