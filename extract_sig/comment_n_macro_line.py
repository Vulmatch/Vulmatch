import os
from string_util import record_comments,record_macro_if,record_macro_if_1

#For each .c file in each version in each cve, we extract its comment lines and macro define lines and store in the version folder.
def main():
 cve_path=input("Please enter the root path for all cves:").strip("'")
 files=os.listdir(cve_path)
 for each in files:
  if os.path.isdir(cve_path+"/"+each):
   current_cve_path=cve_path+"/"+each
   print(current_cve_path)
   one_cve_files=os.listdir(current_cve_path)
   two_versions=[]
   for item in one_cve_files:
    if os.path.isdir(current_cve_path+"/"+item):
     two_versions.append(item)
   for version in two_versions:
    version_path= current_cve_path+"/"+version
    print(version_path)
    process_all_c_file(version_path)

#Given a version path, we process all the .c file in it.
def process_all_c_file(version_path):
  files=os.listdir(version_path)
  for each in files:
   if each.endswith(".c"):
    f=open(version_path+"/"+each,'r',encoding = "ISO-8859-1")
    content=f.read()
    lines=content.split("\n")
    comment_lines=record_comment_lines(version_path+"/"+each)
    #macro_lines=record_macro_lnes(version_path+"/"+each)
    macro_lines=record_macro_lnes1(version_path+"/"+each,comment_lines)
    filtered_macro_lines=[]
    for macro_range in macro_lines:
     if (macro_range[1]-macro_range[0])*1.0/len(lines)>0.9:#delete too big macro
      continue
     else:
      for line in range(macro_range[0],macro_range[1]+1):
       filtered_macro_lines.append(line) 
    write_comment_macro(version_path,each,comment_lines,filtered_macro_lines)

def record_comment_lines(c_path):
  f=open(c_path,'r',encoding = "ISO-8859-1")
  content=f.read()
  lines=content.split("\n")
  comment_lines=record_comments(lines)
  return comment_lines

#Record the lines within one or more #if
def record_macro_lnes(c_path):
  f=open(c_path,'r',encoding = "ISO-8859-1")
  content=f.read()
  lines=content.split("\n")
  macro_lines=record_macro_if(lines)
  return macro_lines

def record_macro_lnes1(c_file,recorded_comments):
  f=open(c_file,'r',encoding = "ISO-8859-1")
  content=f.read()
  lines=content.split("\n")
  line_index, char_index, ranges=record_macro_if_1(lines,0,0,recorded_comments)
  return ranges
  #print("macro lines ranges:",ranges)
 
 
def write_comment_macro(version_path,source,comment_lines,macro_lines):
  f=open(version_path+"/"+source+"_comment_macro.txt",'w')
  string="comment_lines:"
  string+=str(comment_lines)+"\n"
  string+="macro_lines:"
  string+=str(macro_lines)
  f.write(string)
  f.close()

def test_single_c_file():
  c_file=input("Please enter the .c file:").strip("'")
  f=open(c_file,'r',encoding = "ISO-8859-1")
  content=f.read()
  lines=content.split("\n")
  comment_lines=record_comment_lines(c_file)
  macro_lines=record_macro_lnes1(c_file,comment_lines)
  filtered_macro_lines=[]
  for macro_range in macro_lines:
   if (macro_range[1]-macro_range[0])*1.0/len(lines)>0.9:#delete too big macro
    continue
   else:
    for line in range(macro_range[0],macro_range[1]+1):
     filtered_macro_lines.append(line) 
  print("comment_lines:",comment_lines)
  print("filtered_macro_lines:",filtered_macro_lines)


main()
#test_single_c_file()  
  
 
