import pandas as pd
import shutil
import glob
import os
import sys
import re
#sys.path.append('/home/nuc/Desktop/VIVA/extract_callchain_from_sourcecode/')
from pattern import modify_single_c_file
from common_library import structurize_cve
from pdb import set_trace as bp

       

#Given a last vulnerable version, we find the reachable last vulnerable version. Since the given last vulnerable version might not able to be found on the internet (thus in our database).
def find_reachable_last_vulnerable_version(last_vulnerable_version,descending_versions,all_compiled_versions_path):
 wanted_last_vulnerable_version=0
 #First grab the index for the wanted last vulnerable version. 
 for index in range(0,len(descending_versions)):
  if descending_versions[index]==last_vulnerable_version:
   wanted_last_vulnerable_version=index
   break
 for index in range(wanted_last_vulnerable_version,len(descending_versions)):
  if has_compiled_version(descending_versions[index],all_compiled_versions_path):
   return descending_versions[index]

#Given a last vulnerable version, we find the reachable first patched version. Since the given version right after the last vulnerable version might not able to be found on the internet (thus in our database).
def find_reachable_first_patched_version(last_vulnerable_version,descending_versions,all_compiled_versions_path):
 wanted_first_patched_version=0
 #First grab the index for the wanted last vulnerable version. 
 for index in range(0,len(descending_versions)):
  if descending_versions[index]==last_vulnerable_version:
   wanted_first_patched_version=index-1
   break
 for index in range(wanted_first_patched_version,0,-1):
  if has_compiled_version(descending_versions[index],all_compiled_versions_path):
   return descending_versions[index]

#Find in the folder all_compiled_versions_path to check whether we have the compiled version.
def has_compiled_version(version,all_compiled_versions_path):
 compiled_versions=os.listdir(all_compiled_versions_path)
 compiled_versions=[x for x in compiled_versions if x.find(".tar.gz")==-1]
 #print("has_compiled_version compiled_versions=",compiled_versions)
 if "ffmpeg-"+version in compiled_versions:
  return True
 else:
  return False



#Find the bin file under parent_path with bin_name string as file name.
def find_c_file_by_name(parent_path,bin_name):
  searched_files=[]
  #print("parent_path=",parent_path,"bin_name=",bin_name)
  for fname in os.listdir(parent_path):
   #print("fname=",fname,"bin_name=",bin_name)
   if bin_name == fname:
    searched_files.append(fname)
  #searched_files=sorted(searched_files, key=len)
  try:
   src_path=searched_files[0]
  except:
   return parent_path+"/"+bin_name
  return parent_path+"/"+src_path


#For each vulnerable .c source code, we modify the source code, delete the original bin, and compile again
def modify_c_code():
 xml_path=input("Please enter the cve.xml path:").strip("'")
 sheet_name=input("Please enter the sheet name:")
 df=pd.read_excel(xml_path, sheet_name)
 cve_index=list(filter(None, df["CVE"]))
 file_path=list(filter(None, df["File Path"]))
 last_versions=list(filter(None, df["Last"]))
 funcs= list(filter(None, df["Function Name"]))

 all_versions_record=input("Please enter the path recording all versions:").strip("'")
 f=open(all_versions_record,"r")
 descending_versions=list(filter(None,f.read().split("\n")))
 
 all_compiled_versions_path=input("Please enter the path compiling all versions:").strip("'")
 #Now structure information for each cve 
 structured_cve_list=structurize_cve(cve_index,file_path,last_versions,descending_versions,all_compiled_versions_path,funcs)
 #print("structured_cve_list:",structured_cve_list)
 #cve_dir=input("PLease enter the folder recording all cves:").strip("'")
 
 #Now copy paste bin files for each cve
 for cve in structured_cve_list:
  #if (cve.cve_index!="CVE-2011-3389" and cve.cve_index!="CVE-2012-0036"):#For debugging purpose
  # continue
  #print("cve=",cve.cve_index,cve.last_vulnerable_version,cve.first_patched_version,cve.files)
  modify_single_cve(cve,all_compiled_versions_path)
  #if cve.cve_index=="CVE-2021-22947":
  # bp()
  

#modify the current cve so that when compiling, no inline.
def modify_single_cve(cve,all_compiled_versions_path):
  for c_h_tuple in cve.files:
   source_path,h_path=c_h_tuple
   for c_file in cve.files[source_path]:
    #Firstly find the .c file containing the .c file name (for last vulnerable version)
    print("cve.last_vulnerable_version:",cve.last_vulnerable_version)
    src_path=find_c_file_by_name(all_compiled_versions_path+"/ffmpeg-"+cve.last_vulnerable_version+"/"+path,c_file+".c")
    funcs=cve.files[source_path][c_file]
  
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    #two_versions=os.listdir(cve_dir+"/"+cve.cve_index)
    #if cve.last_vulnerable_version in two_versions:
    # dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.last_vulnerable_version
    #else:
    # dest_path=cve_dir+"/"+cve.cve_index+"/"+cve.last_vulnerable_version
    # print("version not available, creating folder:",dest_path)
    # os.mkdir(dest_path)
    #print("src_path=",src_path)
    #print("dest_path=",dest_path)
    if not os.path.isfile(src_path):
     print(src_path,"not exist!")
    else:
     modify_single_c_file(src_path,funcs)
    

    #Secondly find the .o file containing the .c file name (for first patched version)
    src_path=find_c_file_by_name(all_compiled_versions_path+"/ffmpeg-"+cve.first_patched_version+"/"+path,bin_name+".c")
    
  
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    
    if not os.path.isfile(src_path):
     print(src_path,"not exist!")
    else:
     modify_single_c_file(src_path,funcs)
    
#If a vulnerable function records in one version, for experiment convinience, we uninline the function in all versions.
def no_inline_all_functions_in_all_versions():
 vulnerable_path_funcs={}
 #xml_path=input("Please enter the cve.xml path:").strip("'")
 #sheet_name=input("Please enter the sheet name:")
 xml_path='/home/nuc/Downloads/vulnerable_projects/firmware/the_detailed_information_of_vulnerabilities.xlsx'
 sheet_name="dcs-6915"
 df=pd.read_excel(xml_path, sheet_name)
 file_paths=list(filter(None, df["File Path"]))
 function_name=list(filter(None, df["Function Name"]))
 for path, funcs_string in zip(file_paths,function_name):
   if type(path)!=str or type(funcs_string)!=str:#filter out none lines
    continue
   path=path.strip()
   if path[0]=="/":
    path=path[1:]
   funcs=funcs_string.strip().split(',')
   for func_index in range(0,len(funcs)):
    funcs[func_index]=funcs[func_index].strip()
   #if"png_read_IDAT_data" in funcs:
   # bp()
   if is_correct_path(path) and len(funcs)>0:
     if path not in vulnerable_path_funcs:
      vulnerable_path_funcs[path.strip()]=funcs
     else:
      for func in funcs:
        if func not in vulnerable_path_funcs[path]:
         vulnerable_path_funcs[path.strip()].append(func)
 #bp()
 #all_compiled_versions_path=input("Please enter the path compiling all versions:").strip("'")
 all_compiled_versions_path='/home/nuc/Downloads/vulnerable_projects/firmware/openssls'
 files=os.listdir(all_compiled_versions_path)
 for curl_version in files:
   print(curl_version)
   proj_root_path=all_compiled_versions_path+"/"+curl_version
   for c_path in vulnerable_path_funcs:
     if os.path.isfile(proj_root_path+"/"+c_path):
       print(c_path)
       modify_single_c_file(proj_root_path+"/"+c_path,vulnerable_path_funcs[c_path])
 

def is_correct_path(path):
   if re.search('[a-zA-Z0-9_]/[a-zA-Z0-9_]',path):
     return True
   elif re.search('[a-zA-Z0-9_]',path) and path.strip().endswith(".c"):
     return True
   return False


no_inline_all_functions_in_all_versions()
#modify_c_code()
