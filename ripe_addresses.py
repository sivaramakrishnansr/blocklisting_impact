import pyasn
import glob
import sys
def ripe_prefixes():
	#Input: Folder containaining RIPE measurement logs, consistsing of timestamp,probe_id,IP address
	#Input: Output folder
	#Example: python ripe_addresses.py ripe_folder output_folder

	#Generates:
	#dynamic_addresses_all: probes that are dynamically allocated: all allocations within the same AS + more than 8 allocations + average duration between allocation is 24 hours
	#static_addresses_all: probes that are not in dynamic_addresses_all
	#filter_1: probes that have all allocations within the same AS
	#filter_2: probes that have all allocations within the same AS + more than 8 allocations

	ripe_folder=sys.argv[1]
	output_folder=sys.argv[2]
	file_list=sorted(glob.glob(ripe_folder+"/*"))
	last_ip={}
	timestamp_change={}
	all_ips={}
	first_time=set()
	all_ips_24=set()
	results={}
	found_24=set()
	done=0
	diff_distribution={}
	probe_id_ips={}
	total=len(file_list)
	for file in file_list:
		f=open(file,"r")
		for line in f:
			line=line.strip().split(" ")
			try:
				timestamp=int(line[0])
				id=line[1]
				ip=line[2]
			except:
				continue
			if id not in probe_id_ips:
				probe_id_ips[id]=set()
			probe_id_ips[id].add(ip)
			ip_24=".".join(ip.split(".")[0:3])+".0"
			found_24.add(ip_24)
			if id not in all_ips:
				all_ips[id]=set()
			all_ips[id].add(ip)
			if id not in last_ip:
				last_ip[id]=ip
			if id not in first_time:
				if id not in timestamp_change:
					timestamp_change[id]=[timestamp]
				first_time.add(id)

			if ip!=last_ip[id]:
				last_ip[id]=ip
				if id not in timestamp_change:
					timestamp_change[id]=[]
				timestamp_change[id].append(timestamp)
		f.close()
		done=done+1
		print "Done",done,total

	#Generate rib_db using closest RIPE atlas data
	asndb = pyasn.pyasn('rib_db')

	ip_24_to_as={}
	for ip_24 in found_24:
		asn=asndb.lookup(ip_24)
		ip_24_to_as[ip_24]=asn

	asn_id_flag={}
	print len(timestamp_change)
	for id,timestamps in timestamp_change.iteritems():
		timestamps=sorted(timestamps)
		id_24s=set()
		id_asns=set()
		for ip in all_ips[id]:
			ip_24=".".join(ip.split(".")[0:3])+".0"
			id_asns.add(ip_24_to_as[ip_24])
			id_24s.add(ip_24)
		asn_id_flag[id]=len(id_asns)

		if len(timestamps)==1:
			continue
		all_diffs=[]
		for i in range(0,len(timestamps)-1):
			diff=timestamps[i+1]-timestamps[i]
			diff=diff/(3600*24)
			all_diffs.append(diff)
		min_diff=min(all_diffs)
		max_diff=max(all_diffs)
		average=sum(all_diffs)/float(len(all_diffs))
		if min_diff !=0 or max_diff!=0:
			results[id]=(len(all_ips[id]),min_diff,max_diff,average,id_24s,id_asns,len(all_diffs))
		asn_id_flag[id]=len(id_asns)

		temp_diff=len(all_diffs)+1
		if temp_diff not in diff_distribution:
			diff_distribution[temp_diff]=0
		diff_distribution[temp_diff]=diff_distribution[temp_diff]+1



	filter_1=set()
	filter_2=set()
	ripe_prefixes=set()
	address_allocation={}

	fw=open(output_folder+"/dynamic_addresses_all","w")
	fw_static=open(output_folder+"/static_addresses_all","w")
	same_asn=0
	same_asn_diff=0
	current=0
	metadata_ips=[]
	metadata_ip_24=set()
	found_24_daily=set()
	daily_change_probes=set()
	for id,id_data in results.iteritems():
		length=id_data[0]
		min_diff=id_data[1]
		max_diff=id_data[2]
		average_diff=id_data[3]
		id_24s=id_data[4]
		id_asns=id_data[5]
		all_diffs=id_data[6]
		for ip_24 in id_24s:
			ripe_prefixes.add(ip_24)
		dynamic_flag=False
		if len(id_asns)==1:
			for ip_24 in id_24s:
				filter_1.add(ip_24)
			same_asn=same_asn+1
			if all_diffs>=8:
				same_asn_diff=same_asn_diff+1
			if length>=2 and all_diffs>=8:
				for ip_24 in id_24s:
					filter_2.add(ip_24)
				current=current+1
				metadata_ips.append(length)
				dynamic_flag=True
				address_allocation[id]=set()
				for ip_24 in id_24s:
					metadata_ip_24.add(ip_24)
					if average_diff <=1:
						fw.write(ip_24+","+str(min_diff)+","+str(max_diff)+","+str(average_diff)+"\n")
						found_24_daily.add(ip_24)
						address_allocation[id].add(ip_24)
						daily_change_probes.add(id)

		if dynamic_flag==False:
			for ip_24 in id_24s:
				fw_static.write(ip_24+"\n")
	fw.close()
	fw_static.close()

	fw=open(output_folder+"/ripe_prefixes","w")
	for ip_24 in ripe_prefixes:
		fw.write(ip_24+"\n")
	fw.close()

	fw=open(output_folder+"/filter_1","w")
	for ip_24 in filter_1:
		fw.write(ip_24+"\n")
	fw.close()

	fw=open(output_folder+"/filter_2","w")
	for ip_24 in filter_2:
		fw.write(ip_24+"\n")
	fw.close()

ripe_prefixes()
