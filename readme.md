# F5 Upgrade Process

The following playbook will upgrade your F5 device automatically 

* Generate a Pre Check on the existing Virtual Server Status in given partition.
* Checks the failover state of a BIG-IP system {will only upgrade to standby}
* Prepares the BIG-IP system for an upgrade
* Performs load sys config verify
* Downloads the latest UCS File and uploads it the server
* rsync the F5 repository server to upload the firmware to BIGIP
* find the available partition and install image into the available partition
* Converts the configuration and Boots to the newly upgraded boot location
* Generate a post Check for virtual server status in given partition.

Which version does it work with 
| version | ltm | f5-dns |
|---|---|---|---|---|
| v12 | TBT | TBT |
| v13 | TBT | TBT |
| v14 | TBT | TBT |
| v15 | TBT | TBT |
| v16 | TBT | TBT |

# How to use
Clone the following plabook or just copy and paste it.
* edit the host file in the inventory folder to include your F5
* edit the partition_list file in the group_vars/lb folder to include your F5 partitions for pre and post checks
* Note: I recommend you dont store your passwords in the file, use ansible vault (maybe i will add this into this one later)
* Download you desired version of F5 and place it in the files folder

# Execute playbook 

To excute playbook run the following command 
```
ansible-playbook -i inventory/hosts upgrade_bigip_v1.yaml
```

## Notes
* Need to add mount -o remount,ro /usr for users that have ilx module deployed after version 13 all the way to 16
* Need to add task to check if the firmware is already in BIGIP before uploading to F5
* Need to modify task to ignore if wrong partition is defined in the partition_list file.
* Need to add a task to download the BIGIP image in F5 Repo, if does not exit.
* Need to add a post-check if backup works after the upgrade.
* Need to add a post-check if all self-ip addresses are pingable after the upgrade.
* Need to add a post-check to bring all BIGIP logs contains error, failure, timeout
* Need to work on license renewal: the BIG IP is giving error and seems like it is due to proxy
* Need to add task to verify the firmware checksum before installing.
* Reorder the tasks to verify the failover state first.

## Requirements

* jmespath
* ansible [core 2.12.4]
* jinja version = 3.1.1
* python version = 3.10.2