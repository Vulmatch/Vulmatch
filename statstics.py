import os
import statistics
import pandas as pd
from pdb import set_trace as bp

#Count .c file, .h file, .o file on avg. in each version.
def count_avg_file():
 versions_root=input("Please enter the project's all version path:").strip("'")
 items=os.listdir(versions_root)
 versions=[]#Record each version
 c_nums=[]#Record each version's .c file number
 o_nums=[]#Record each version's .o file number
 h_nums=[]#Record each version's .h file number
 for each in items:
  #print("--------------------------------------")
  #print(each)
  #print("")
  if os.path.isdir(versions_root+"/"+each):
    versions.append(each)
    current_version_path=versions_root+"/"+each
    c_num=0
    h_num=0
    o_num=0
    for root,dirs,files in os.walk(current_version_path):
     for each_file in files:
       if each_file.endswith(".c"):
        c_num+=1
       elif each_file.endswith(".o"):
        #print(each_file)
        o_num+=1
       elif each_file.endswith(".h"):
        h_num+=1
    c_nums.append(c_num)
    o_nums.append(o_num)
    h_nums.append(h_num)

 for version, c_num, o_num, h_num in zip(versions, c_nums, o_nums, h_nums):
   print(version,"c files:", c_num, "o files:", o_num, "h files:", h_num)
 print("Avg c num:", statistics.mean(c_nums))
 print("Avg o num:", statistics.mean(o_nums))
 print("Avg h num:", statistics.mean(h_nums))

#Count each project's avg size 
def count_avg_size():
 versions_root=input("Please enter the project's all version path:").strip("'")
 items=os.listdir(versions_root)
 sizes=[]#Record each version's size
 for each in items:
  if os.path.isdir(versions_root+"/"+each):
    current_version_path=versions_root+"/"+each
    sizes.append(os.path.getsize(current_version_path))
    print(current_version_path, os.path.getsize(current_version_path))
 print("avg size (MB):", statistics.mean(sizes))

def count_function_num():
 xml_path=input("Please enter the xml path:").strip("'")
 sheet_name=input("Please enter the sheet name:").strip("'")
 df=pd.read_excel(xml_path, sheet_name)
 functions=list(filter(None, df["Function Name"]))
 function_num=0
 for i in functions:
  if str(i)=="nan":
    continue
  elif type(i)==str:
   if i.find(",")!=-1:
     function_num+=i.count(",")+1
   else:
     function_num+=1
 print("function num:",function_num)
 

#count_avg_file()
#count_avg_size()
count_function_num()
