import os
from pdb import set_trace as bp
alfa=0.4

def read():
 #my_tool_result_path="/home/nuc/Desktop/my_tool_result_version-15"
 my_tool_result_path=input("Please enter my tool result folder:").strip("'")
 files=os.listdir(my_tool_result_path)
 correct_func=0
 wrong_func=0#Include patch sim bigger than vul sim, and the vul/patch diff smaller than 0.1
 equal_func=0
 total_func=0
 functions_dbg=[]
 total_sim=0#Record a list of similarity scores. Used for checking explainbility
 
 overlooked_num=0
 overlooked=[]

 #Used to check TP and FP
 sim_threshold=0.6
 wrong_vul_num=0
 wrong_patch_num=0

 for each in files:
  result_path=my_tool_result_path+"/"+each
  f=open(result_path,'r')
  content=f.read()
  lines=content.split('\n')
  for line in lines:
   if line.find("max_func_list0=")!=-1:
     function_sim_dict0=parse_line(line.split("max_func_list0=")[1])
     #bp()
   elif line.find("max_func_list3=")!=-1:
     function_sim_dict3=parse_line(line.split("max_func_list3=")[1])
     #bp()
  for func in function_sim_dict0:
   #Check TP and FP
   if function_sim_dict0[func][1]<sim_threshold:
       wrong_vul_num+=1
   if function_sim_dict3[func][1]>=sim_threshold:
       wrong_patch_num+=1 
   
   if function_sim_dict0[func][0]==func:#ground truth vul func ranks first
     #Diffentiate other func in vul bin
     if abs(function_sim_dict0[func][1]-function_sim_dict0[func][3])<alfa:
       if function_sim_dict0[func][3]>=sim_threshold:
        wrong_func+=1
      
     #Differentiate patch and vul versions
     if function_sim_dict0[func][1]>function_sim_dict3[func][1]:
       print(function_sim_dict0[func][1],">",function_sim_dict3[func][1])
       total_sim+=function_sim_dict0[func][1]
       correct_func+=1
       if abs(function_sim_dict0[func][1]-function_sim_dict3[func][1])<alfa:
         if function_sim_dict3[func][1]>=sim_threshold:#For example, only when 0.8>0.75>0.6(threshold) is wrong. 0.63>0.55 is right
          wrong_func+=1
         
     elif function_sim_dict0[func][1]==function_sim_dict3[func][1]:
       print(function_sim_dict0[func][1],"=",function_sim_dict3[func][1])
       equal_func+=1
       if function_sim_dict3[func][1]>=sim_threshold:#For example, only when 0.8>0.75>0.6(threshold) is wrong. 0.63>0.55 is right
        wrong_func+=1
     else:
       print(function_sim_dict0[func][1],"<",function_sim_dict3[func][1])
       if function_sim_dict3[func][1]>=sim_threshold:#For example, only when 0.8>0.75>0.6(threshold) is wrong. 0.63>0.55 is right
        wrong_func+=1
   else:
    overlooked_num+=1
    overlooked.append((each,func,function_sim_dict0[func],function_sim_dict3[func]))
   total_func+=1
   functions_dbg.append(each.split("bin")[0]+" "+func)
 print("correct_func:",correct_func,"wrong_func:",wrong_func,"equal_func:",equal_func,"total_func:",total_func,"avg explainble sim:",total_sim*1.0/correct_func,"overlooked_num=",overlooked_num,"wrong_vul_num:",wrong_vul_num,"wrong_patch_num:",wrong_patch_num)
 for item in overlooked:
  print(item)
 functions_dbg.sort()
 for func in functions_dbg:
  print(func) 

def parse_line(string_dict):
 parsed_dict={}
 for index in range(0,len(string_dict)):
  if string_dict[index:index+2]=="':":
   source_func=find_func_name_backward(string_dict,index-1)
   sim_result_func0,sim0,sim_result_func1,sim1=find_sim_result(string_dict,index+2)
   parsed_dict[source_func]=(sim_result_func0,sim0,sim_result_func1,sim1)
 return parsed_dict
   
 
def find_func_name_backward(string_dict,end_index):
  for index in range(end_index,-1,-1):
   if string_dict[index]=="'":
    return string_dict[index+1:end_index+1]
 
def find_sim_result(string_dict,start_index):
 func_name0=""
 sim0=None
 func_name1=""
 sim1=None

 for index in range(start_index,len(string_dict)):
  if string_dict[index]==")":
   tuple_string=string_dict[start_index:index]
   #print("tuple_string:",tuple_string)
   if tuple_string.split(",")[0].find("'")==-1:
     func_name0=""
   else:
    func_name0=tuple_string.split(",")[0].split("'")[1]
   sim0=float(tuple_string.split(",")[1])
   if tuple_string.split(",")[2].find("'")==-1:
     func_name1=""
   else:
    func_name1=tuple_string.split(",")[2].split("'")[1]
   sim1=float(tuple_string.split(",")[3])
   return func_name0,sim0,func_name1,sim1

read()

