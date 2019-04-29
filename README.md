# rbk_nas_bulk_add
A Project to bulk add NAS shares to a Rubrik 

The idea behind this project is to build a set of scripts that can help add NAS shares to a Rubrik at scale until such time as the functionlaity is built in.  An advantage of Rubrik being an API-first archetecture is that automating tasks is a straight-forward process.

At this time, the project has two scripts, rbk_nas_bulk_add.py and nas_array_grab.py .  

They are Python scripts that require libraries.  The rbk_nas_bulk_add script requires 'rubrik_cdm' library so if you don't have that, install that first.  https://github.com/rubrikinc/rubrik-sdk-for-python.  It should install with a simple 'pip install rubrik_cdm'
The nas_array_grab script requires the Isilon and NetApp SDKs to operate.  The Isilon library ca be found here https://github.com/Isilon/isilon_sdk_python or you can install it via pip with 'pip install isi_sdk_8_0'.  The NetApp SDK is included in the 'NetApp' directory below.  Keep that directory with the script or if you want it elsewhere, modify the script to look for it in the place you want.

##rbk_nas_bulk_add.py

Assumptions:
Today, the script assumes a few things.  Some or all of these assumptions may be lifted on later releases:

1. The fileset template exists
2. The SLA domain exists
3. The NAS host is already configured on the Rubrik
4. One fileset and/or SLA will be assigned to all of the shares per run.  Because of this, you shouldn't mix NFS and SMB shares in the same file unless you are not assigning a fileset.
5. The shares/exports exist on the NAS array and they are mountable by Rubrik.

Syntax:
<pre>
Usage: rbk_nas_bulk_add.py -i file [-hvDC] [-d 'delim'] [-c user:passwd] [-f fileset] [-s sla] [-e array] rubrik
-h | --help : Prints this message
-i | --input= : Specifies the input file for hosts and shares
-v | --verbose : Verbose output
-D | --direct_archive : Use Direct Archive
-C | --cleanup : Delete shares in the list instead of add
-d | --delim= : Set the delimiter in the input file. ':' is the default
-c | --creds= : Specify the Rubrik credentials instead of being prompted.  Use user:password or the filename of an obfuscated creds file.
-f | --fileset= : Assign each share to this fileset 
-s | --sla= : Assign an SLA to each share in this fileset.  Must be used with -f
-e | --add_exports= : Adds the Rubrik IPs to the root client list of the NFS exports [Isilon Only]
rubrik : The hostname or IP address of the Rubrik
</pre>
The input file:
At this time, the input file has 2 columns per row.  The first column is the name of the NAS host as it's defined in Rubrik and the 2nd is the name of the share or the path of the export.  The script assumes any share name that starts with / is an NFS path.  Reach out if you have SMB shares that start with / (although I've never seen that and I'm not sure it's legal).  By default the script assumes a : as the delimiter of the 2 fields, but that can be over-ridden with the -d flag (e.g. -d ',' for a csv)

The script runs silently (except for errors) unless the -v flag is used.

Cleanup:
If the -C flag is used, the script will remove any shares in the input file instead of create them. 

Direct Archive:
If the SLA used has an archive, the script will turn on Direct Archive on the fileset if the -D flag is used.  Otherwise, it will not.

Filesets and SLA Domains:
If no fileset of SLA is defined, they will not be added by the script.  If an SLA domain is desired, a fileset must be provided as well.

## nas_array_grab.py

This script can work with rbk_nas_bulk_add by creating the input file needed by that script.  It is made to work with NetApp or Isilon arrays and uses the APIs on those platforms to pull the share data from them.  It can discover SVMs on NetApp and Access Zones on Isilon. 
The idea is that you can discover all shares (NFS or SMB/CIFS) and then you can edit the file as you like, then use the rbk_nas_bulk_add script to add the shares to Rubrik.

Assumptions:
At this time, the script makes a few assumptions:

1. You do not want to back the root of an SVM (NetApp) or the top level of an Isilon (/ifs).  Anything pointing to those are excluded.  If you think this is an issue, reach out and I'll consider making changes
2. You have access to administrative accounts on the arrays.  In the case of NetApp, it should connect to the cluster mangagement interface.  For Isilon, it should connect to a IP in the System zone.  If you need more restricted RBAC roles, reach out and I'll try to come up with some if you need help with that.
3. To discover NFS exports on a NetApp SVM, you must have at least one export policy defined.
4. For NetApp, the script assumes you are running CDOT (Clustered ONTAP).  I have tested it on 9.1 and 9.4 but I have no reason to think it should be version dependent outside of CDOT.
5. For Isilon, the script assumes you are running OneFS 8.0 or higher.  Lower versions will not work due to API calls.

Syntax:
<pre>
Usage: nas_array_grab.py -p protocol [-h] [-o outfile] [-c creds] [-s svm] [-d delim] [-i interface] [-s svm] [-z zone] [-S sc_zone] array hostname

-h | --help : Prints this message
-p | --protocol= : Specify the protocol nfs or smb|cifs.  This flag is required
-o | --output= : Sends data to the file specified.  By default, data goes to stdout
-c | --creds= : Specify user credentials in the format user:password or a filename with the data obfuscated with creds_encode.py
-d | --delim= : Specify a delimiter for outout.  Default is ':'
-s | --swm= :  Don't auto-discover SVMs, only pull data from a comma-separated list of NetApp SVMs.  [NetApp Only]
-i | --interface= : Don't auto-discover interfaces, use the interfaces here comma-separated.  [NetApp Only]
-z | --access_zones= : Don't auto-discover access zones.  Only pulll from a comma-separated list. [Isilon Only]
-S | --sc_zones= : Don't auto-discover SmartConnect Zone names.  Only pull from a comma-separated list. [Isilon Only]
array : Specify the array type: isilon|isln or netapp|ntap
hostname : Specify the hostname of the array.  [Isilon: System Zone] [NetApp: Cluster Management]


</pre>
Feel free to reach out with any questions/comments
