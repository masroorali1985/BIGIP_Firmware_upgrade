# F5 Upgrade Process

The following playbook will upgrade your F5 device automatically 

* Checks the failover state of a BIG-IP system {will only upgrade to standby}
* Generate F5-check script as pre-check
* Performs load sys config verify
* Fetch BIGIP Backup
* Fetch BIGIP Qkview
* Generate Virtual Server Status as pre-check and create an HTML report
* Reactivate BIGIP with existing reg key (does not work currently due to proxy)
* Upload image and image checksum using rsync to BIGIP
* verify image checksum
* check available volume
* install BIGIP Image
* Generate Virtual Server Status as post-check and create an HTML report
* Generate F5-check script as post-check


Which version does it work with 
| version | ltm | f5-dns |
|---|---|---|---|---|
| v15 | tested | TBT |
| v16 | TBT | TBT |

# How to use
* clone the following plabook or just copy and paste it.
* edit the host file in the inventory folder to include your F5
* edit the partition_list file in the group_vars/lb directory to include your F5 partitions for pre and post checks
* edit the image file in the group_vars/lb directory to include the image for the upgrade
* Make sure the image and image-checksum is available in rsync server

# Execute playbook 

To excute playbook run the following command 
```
ansible-playbook -i inventory/hosts upgrade_bigip_v4.yml
```

## Notes
* Need to work on license renewal: the BIG IP is giving error and seems like it is due to proxy
* Need to add a task to collect the partitions and add into the partition_list.
* Need to modify task to ignore if wrong partition is defined in the partition_list file.
* Need to add a post-check if all self-ip addresses are pingable after the upgrade.
* Need to add a post-check to bring all BIGIP logs contains error, failure, timeout



## Requirements

* jmespath
* ansible [core 2.12.4]
* jinja version = 3.1.1
* python version = 3.10.2
