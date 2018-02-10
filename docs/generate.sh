
ansible-doc -M ../library/ ranger_kafka_policies 2>/dev/null | sed 's/[(].*ranger_modules[/]library.*[)]//' >ranger_kafka_policies.txt
ansible-doc -M ../library/ ranger_hbase_policies 2>/dev/null | sed 's/[(].*ranger_modules[/]library.*[)]//' >ranger_hbase_policies.txt
ansible-doc -M ../library/ ranger_hdfs_policies 2>/dev/null | sed 's/[(].*ranger_modules[/]library.*[)]//' >ranger_hdfs_policies.txt
ansible-doc -M ../library/ ranger_hive_policies 2>/dev/null | sed 's/[(].*ranger_modules[/]library.*[)]//' >ranger_hive_policies.txt
ansible-doc -M ../library/ ranger_yarn_policies 2>/dev/null | sed 's/[(].*ranger_modules[/]library.*[)]//' >ranger_yarn_policies.txt
ansible-doc -M ../library/ ranger_storm_policies 2>/dev/null | sed 's/[(].*ranger_modules[/]library.*[)]//' >ranger_storm_policies.txt
