import pickle
import os
from pdb import set_trace as bp
class func_vul_patch_signature:
    def __init__(self, function_name, vul_signature,patch_signature):
        self.function_name = function_name
        self.vul_signature = vul_signature
        self.patch_signature=patch_signature

class diff_insn:
    def __init__(self, header, origin_content,new_content):
        self.header = header
        self.origin_content = origin_content
        self.new_content=new_content

class p_c_sig:#Parent- children context signature. For the null vul signatures.
    def __init__(self, p,c):
        self.p = p
        self.c=c

class sub_p_c_sig:#Partial parent- children context signature. For the null vul signatures. Designed for changed insns if they can form a parent-child relations.
    def __init__(self, p,c):
        self.p = p
        self.c=c

class cve:
    def __init__(self, cve_index, last_vulnerable_version,first_patched_version,files):
        self.cve_index = cve_index
        self.last_vulnerable_version = last_vulnerable_version
        self.first_patched_version=first_patched_version
        self.files=files#This can be either source code file or binary file.'''

#Given a list of version strings, order them by increasing order.
def increase_order(two_versions,descending_versions):

 for index in range(0,len(descending_versions)):
  if descending_versions[index]==two_versions[0]:
   number0=len(descending_versions)-index
  elif descending_versions[index]==two_versions[1]:
   number1=len(descending_versions)-index
 if number0>number1:
  return [two_versions[1],two_versions[0]]
 else:
  return two_versions

 all_versions_record=input("Please enter the path recording all versions:").strip("'")
 f=open(all_versions_record,"r")
 descending_versions=list(filter(None,f.read().split("\n")))

def write_pickle(insn_signature_list,current_cve_path,c_file):
 if len(insn_signature_list)>0:
   f=open(current_cve_path+"/"+c_file+"_insn_sig.pickle",'wb')
   pickle.dump(insn_signature_list,f, protocol=pickle.HIGHEST_PROTOCOL)
   f.close()
 #if struct_signature_list!=None:
 #  f=open(current_cve_path+"/"+c_file+"_struct_sig.pickle",'wb')
 #  pickle.dump(struct_signature_list,f, protocol=pickle.HIGHEST_PROTOCOL)
 #  f.close()

def write_error(not_found_name_line,untouched_function_error,current_cve_path,c_file):
  if untouched_function_error==[]:
   return
  f=open(current_cve_path+"/"+c_file+"_error.txt",'w')
  string="not found function name error:\n"
  string+=str(not_found_name_line)
  string+="\nuntouched function error:\n"
  string+=str(untouched_function_error)
  f.write(string)
  f.close()

def write_h_error(not_found_name_line,current_cve_path,h_file):
 f=open(current_cve_path+"/"+h_file+"_error.txt",'w')
 string="not found function name error:\n"
 string+=str(not_found_name_line)
 f.write(string)
 f.close()

def write_changed_structs(current_cve_path,changed_structs):
  f=open(current_cve_path+"/"+"changed_structs.txt",'w')
  f.write(str(changed_structs))
  f.close()

def construct_diff_insn_list(diff_result):
 result_list=[]
 lines=diff_result.split("\n")
 lines = list(filter(None, lines))
 line_index=0
 
 while line_index < len(lines):
  if (not lines[line_index].startswith('<')) and (not lines[line_index].startswith('>')) and lines[line_index]!='---':
    change_lines=None
    if lines[line_index].find('a')!=-1:
      change_lines=lines[line_index].split("a")
      change_lines.insert(0,'a')
    elif lines[line_index].find('d')!=-1:
      change_lines=lines[line_index].split("d")
      change_lines.insert(0,'d')
    elif lines[line_index].find('c')!=-1:
      change_lines=lines[line_index].split("c")
      change_lines.insert(0,'c')
    #if line_index==8:
    # bp()
    origin,new=find_origin_new(lines,line_index+1,change_lines) 
    new_struct=diff_insn(change_lines,origin,new)
    result_list.append(new_struct)  
  line_index+=1
 return result_list 

def find_origin_new(lines,start_line,change_lines):
 origin={}
 new={}
 end_index=start_line

 while end_index<len(lines):
  if (not lines[end_index].startswith('<')) and (not lines[end_index].startswith('>')) and lines[end_index]!='---':
   break
  else:end_index+=1
 if end_index==len(lines):
  end_index=len(lines)-1
 origin_start=int(change_lines[1].split(',')[0])
 new_start=int(change_lines[2].split(',')[0])
 
 origin_offset_line=0
 new_offset_line=0
 for line_index in range(start_line,end_index+1):
  if lines[line_index].startswith('<'):
   origin[origin_offset_line+origin_start]=lines[line_index].lstrip('<')
   origin_offset_line+=1
  elif lines[line_index].startswith('>'):
   new[new_offset_line+new_start]=lines[line_index].lstrip('>')
   new_offset_line+=1
 return origin,new   

#Diff result usually in the form of 123a124,126, which means at vul line 123, patch version add line 124 to 126. We want to translate 124,126 to [124,125,126]
def comma2list(comma_string):
 comma_string=comma_string.strip()
 if comma_string.find(",")==-1:
  return [int(comma_string)]
 else:
  start=int(comma_string.split(",")[0])
  end=int(comma_string.split(",")[1])
  result_list=[]
  for line in range(start,end+1):
   result_list.append(line)
  return result_list

#Given a list of cve_index, file_path, and last_versions, we structure them by cves. The input cve_index is in form of [cve1, cve2,nan,nan,cve3...]. The input file_path is in form of [path1, path2,path3, ...pathn] with no information which paths are in a single cve. The input last_versions is in the form of [version1, version2, nan, nan, version3...].
def structurize_cve(cve_index,file_path,last_versions,descending_versions,all_compiled_versions_path,funcs):
 result_list=[]
 current_cve_begin_index=0
 current_cve_end_index=1
 while current_cve_end_index<len(cve_index):
  #print("current_cve_end_index=",current_cve_end_index)
  if str(cve_index[current_cve_end_index])=='nan':
   current_cve_end_index+=1
  else:
   last_vulnerable_version=find_reachable_last_vulnerable_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)

   first_patched_version=find_reachable_first_patched_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)

   path_c_func_dict=category_func_bin_by_folder(file_path[current_cve_begin_index:current_cve_end_index],funcs[current_cve_begin_index:current_cve_end_index])
   if last_vulnerable_version==None:#If last version not found, that means we didn't find any reachable version online, skip it.
    current_cve_end_index+=1
    continue
   current_cve_structure=cve(cve_index[current_cve_begin_index],last_vulnerable_version,first_patched_version,path_c_func_dict)
   print("last_vulnerable_version:",last_vulnerable_version,"wanted last version:",last_versions[current_cve_begin_index])
   result_list.append(current_cve_structure)
   current_cve_begin_index=current_cve_end_index
   current_cve_end_index+=1
 return result_list

#Given a last vulnerable version, we find the reachable last vulnerable version. Since the given last vulnerable version might not able to be found on the internet (thus in our database).
def find_reachable_last_vulnerable_version(last_vulnerable_version,descending_versions,all_compiled_versions_path):
 wanted_last_vulnerable_version=0
 #First grab the index for the wanted last vulnerable version. 
 for index in range(0,len(descending_versions)):
  if descending_versions[index]==last_vulnerable_version:
   wanted_last_vulnerable_version=index
   break
 #bp()
 for index in range(wanted_last_vulnerable_version,len(descending_versions)):
  if has_compiled_version(descending_versions[index],all_compiled_versions_path):
   return descending_versions[index]
 bp()  

#Given a last vulnerable version, we find the reachable first patched version. Since the given version right after the last vulnerable version might not able to be found on the internet (thus in our database).
def find_reachable_first_patched_version(last_vulnerable_version,descending_versions,all_compiled_versions_path):
 wanted_first_patched_version=0
 #First grab the index for the wanted last vulnerable version. 
 for index in range(0,len(descending_versions)):
  if descending_versions[index]==last_vulnerable_version:
   wanted_first_patched_version=index-1
   break
 for index in range(wanted_first_patched_version,-1,-1):
  if has_compiled_version(descending_versions[index],all_compiled_versions_path):
   return descending_versions[index]
 bp()

#Find in the folder all_compiled_versions_path to check whether we have the compiled version.
def has_compiled_version(version,all_compiled_versions_path):
 compiled_versions=os.listdir(all_compiled_versions_path)
 compiled_versions=[x for x in compiled_versions if x.find(".tar.gz")==-1]
 #print("has_compiled_version compiled_versions=",compiled_versions)
 if "openssl-"+version in compiled_versions:
  return True
 else:
  return False
  
def addr2const_string(block_disasm,strings_refs):
 for addr,string in strings_refs:
  block_disasm=block_disasm.replace(addr,'"'+string+'"')
 return block_disasm

def make_hex(strings_refs):
 new_tuples=[]
 for addr,string in strings_refs:
   new_tuples.append((hex(addr),string))
 return new_tuples

#Each concrete address to "addr", [rip+*offset*] to "addr".
def normalize_address(block_insns):
 normalized_insns=[]
 for insn in block_insns:
  if insn.strip().startswith("call "):
   normalized_insns.append("call addr")
  elif insn.strip().startswith("j"): 
   mnenomic=insn.strip().split(" ")[0]
   normalized_insns.append(mnenomic+" addr")
  elif insn.find("[ rip + ")!=-1:
   start_index=insn.find("[ rip + ")
   end_index=insn.find("]",start_index)
   normalized_insns.append(insn[:start_index]+"addr"+insn[end_index+1:])
  else:
   normalized_insns.append(insn)
 if "" in normalized_insns:
  bp()
 return normalized_insns

#Each concrete address to "addr", [rip+*offset*] to "addr".
def insn_normalize_address(insn):
 normalized_insn=""
 if insn.strip().startswith("call "):
   normalized_insn="call addr"
 elif insn.strip().startswith("j"): 
   mnenomic=insn.strip().split(" ")[0]
   normalized_insn=mnenomic+" addr"
 elif insn.find("[ rip + ")!=-1:
   start_index=insn.find("[ rip + ")
   end_index=insn.find("]",start_index)
   normalized_insns=insn[:start_index]+"addr"+insn[end_index+1:]
 else:
   normalized_insn=insn
 if normalized_insn=="":
  bp()
 return normalized_insn

#Given a list of paths of binaries and funcs, category them by the path. {path1:{c_file1:[func1,func2],c_file2:[func1,...],...},path2:{c_file1:[func1],c_file2:[func1,func2,func3,...],...},...}
def category_func_bin_by_folder(file_paths,funcs):
 result_dict={}
 #print("category_bin_by_folder")
 #print("file_paths=",file_paths)
 for each_path,fun_names in zip(file_paths,funcs):
  path=str(each_path)
  if path=="nan":
   continue
  #print("category_bin_by_folder result_dict=",result_dict)
  last_slash_index=path.rfind('/')
  parent_path=path[:last_slash_index]
  if path[last_slash_index+1:].find(".h")!=-1:
   continue
  elif path[last_slash_index+1:].find(".c")==-1:
   continue
  bin_name=path[last_slash_index+1:].split(".c")[0]
  if str(fun_names)!="nan":
   all_names=fun_names.split(",")
  else:
   all_names=[]
  for i in range(0,len(all_names)):
   all_names[i]=all_names[i].strip()
  if parent_path not in result_dict:
   result_dict[parent_path]={bin_name:all_names}
  else:
   result_dict[parent_path][bin_name]=all_names
 return result_dict

