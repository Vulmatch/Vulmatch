from string_util import record_comments,delete_comments
import re
from pdb import set_trace as bp

def listize_struct_lines(h_file):
  f=open(h_file,'r',encoding = "ISO-8859-1")
  content=f.read()
  lines=content.split("\n")
  f.close()
  comment_lines=record_comments(lines)
  
  line_struct_name={}
  s_name=""
  line_index=0
  while line_index <len(lines):
   #if line_index==639 and "url.c" in c_path:
   # bp()
   #if "CVE-2015-3145" in c_path: 
   #if '         || (wantNTLMhttp || check->ntlm.state != NTLMSTATE_NONE)' in lines[line_index]:
   #  bp()
   #if line_index==563:
   #  bp()
   if is_classic_struct_define(lines,line_index,comment_lines)==True:
     s_name=extract_struct_name(lines[line_index])
     line_struct_name[line_index]=s_name
     end_line=find_struct_end_line(lines,line_index)
     if end_line==None:
      bp()
     for index in range(line_index,end_line):
      line_struct_name[index]=s_name
     line_index=end_line
     continue
   line_index+=1
  return line_struct_name

def is_classic_struct_define(lines,line_index,comment_lines):
  line_string=delete_comments(lines[line_index])
  line_string=line_string.strip()
  if re.match("struct[\s]+[a-zA-Z0-9_]+[{]*",line_string) and (not line_string.endswith(";")) and (not line_string.endswith(",")):
   return True
  return False

def extract_struct_name(line_string):
 line_string=delete_comments(line_string)
 line_string=line_string.strip()
 name=line_string.split(' ')[1]
 name.replace("{","")
 return name

#In a .h file, we find all the specific struct's parents, grandparents, and all ancestors.
#Since there can be loop-like structs, we need to have touched_struct to record the touched structs. Once
#touched, never think about it any more.
def find_all_parent_struct(lines,line_struct_name,struct,touched_struct):
 touched_struct.append(struct)
 parent_struct=[]
 for line_index in range(0,len(lines)):
   #if line_index==898 and struct=="ssl_connect_data":
   # bp()
   if is_member_struct(lines[line_index],struct):
    if line_index not in line_struct_name:
     bp()
    #bp()
    parent_struct.append(line_struct_name[line_index])
 
 result=[]
 for parent in parent_struct:
  #bp()
  if parent in touched_struct:
   continue 
  tmp_result=find_all_parent_struct(lines,line_struct_name,parent,touched_struct)
  for each in tmp_result:
   result.append(each)
 result.append(struct)
 #bp()
 return result

#Check whether the line string is a declaration that struct is a member within some parent structs.
def is_member_struct(line_string,struct):
 string=delete_comments(line_string)
 string=string.strip()
 if re.match("struct[\s]+"+struct+"[\s]+[*]*[a-zA-Z0-9_\[\]]*[\s]*;",string):
  return True
 return False

#Find the first left bracket of a struct definition.
def find_left_bracket(lines,line_index):
 for i in range(line_index,len(lines)):
   string=delete_comments(lines[i])
   if '{' in string:
    return i,string.find('{')

#Find the end '}' symbol of the struct
def find_struct_end_line(lines,line_index):
 first_line_index,char_index=find_left_bracket(lines,line_index)
 level=1
 first_line=delete_comments(lines[first_line_index])
 for char in range(char_index+1,len(first_line)):
  if first_line[char]=='{':
   level+=1
  elif first_line[char]=='}':
   level-=1
 for line in range(first_line_index+1,len(lines)):
  line_string=delete_comments(lines[line])
  for char in range(0,len(line_string)):
   if line_string[char]=='{':
    level+=1
   elif line_string[char]=='}':
    level-=1
  if level==0:
   return line

def find_all_parent_struct_main(h_file,struct,touched_struct):
  line_struct_name=listize_struct_lines(h_file)
  f=open(h_file,'r',encoding = "ISO-8859-1")
  content=f.read()
  lines=content.split("\n")
  ancestors=find_all_parent_struct(lines,line_struct_name,struct,touched_struct)
  return ancestors
