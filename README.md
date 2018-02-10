# ranger_modules

This ansible role host a set of modules aimed to manipulate policies on Apache Ranger.

* ranger\_hdfs\_policies: Allow creation/deletion/update of HDFS Ranger policies. Doc [at this location](docs/ranger_hdfs_policies.txt)

* ranger\_hbase\_policies: Allow creation/deletion/update of HBase Ranger policies. Doc [at this location](docs/ranger_hbase_policies.txt)

* ranger\_kafka\_policies: Allow creation/deletion/update of Kafka Ranger policies. Doc [at this location](docs/ranger_kafka_policies.txt)

* ranger\_yarn\_policies: Allow creation/deletion/update of Yarn Ranger policies. Doc [at this location](docs/ranger_yarn_policies.txt)

* ranger\_storm\_policies: Allow creation/deletion/update of Storm Ranger policies. Doc [at this location](docs/ranger_storm_policies.txt)

## Requirements

These modules need the python-requests package to be present on the remote node.

# Example Playbook

	# Grant full rights for user 'coxi' on folders '/apps/coxi01' and '/user/coxi01', in a recursive way
	
	- hosts: edge_node1
	  roles:
	  - ranger_modules
	  tasks:
	  - ranger_hdfs_policies:
	      state: present
	      admin_url: http://ranger.mycompany.com:6080
	      admin_username: admin
	      admin_password: admin
	      policies:
	      - name: "coxi01"
	        paths: 
	        - "/apps/coxi01" 
	        - "/user/coxi01" 
	        permissions:
	        - users:
	          - coxi
	          accesses:
	          - Write
	          - read
	          - execute
          
# License

GNU GPL

Click on the [Link](COPYING) to see the full text.

