# rbk_nas_bulk_add
A Project to bulk add NAS shares to a Rubrik 

The idea behind this project is to build a set of scripts that can help add NAS shares to a Rubrik at scale until such time as the functionlaity is built in.  An advantage of Rubrik being an API-first archetecture is that automating tasks is a straight-forward process.

At this time, the project has one script, rbk_nas_bulk_add.py.  It's a Python script that requires the 'rubrik_cdm' library so if you don't have that, install that first.  https://github.com/rubrikinc/rubrik-sdk-for-python.  It should install with a simple 'pip install rubrik_cdm'

Assumptions:
Today, the script assumes a few things.  Some or all of these assumptions may be lifted on later releases:

1. The fileset template exists
2. The SLA domain exists
3. The NAS host is already configured on the Rubrik
4. One fileset and/or SLA will be assigned to all of the shares per run.  Because of this, you shouldn't mix NFS and SMB shares in the same file unless you are not assigning a fileset.
5. The shares/exports exist on the NAS array and they are mountable by Rubrik.

Syntax:
<pre>
Usage: rbk_nas_bulk_add.py -i file [-hvDC] [-d 'delim'] [-c user:passwd] [-f fileset] [-s sla] rubrik
-h | --help : Prints this message
-i | --input= : Specifies the input file for hosts and shares
-v | --verbose : Verbose ouput
-D | --direct_archive : Use Direct Archive
-C | --cleanup : Delete shares in the list instead of add
-d | --delim= : Set the delimiter in the input file. ':' is the default
-c | --creds= : Specify the Rubrik credentials instead of being prompted.  This is not secure
-f | --fileset= : Assign each share to this fileset
-s | --sla= : Assign an SLA to each share in this fileset.  Must be used with -f
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

Feel free to reach out with any questions/comments
