from neo4j_client import driver

def check_relationships():
    """Check relationships between nodes"""
    if not driver:
        print("❌ No driver connection")
        return
    
    try:
        with driver.session() as session:
            print("🔍 Checking relationships:")
            print("=" * 50)
            
            # Check what relationships exist
            print("📊 All relationship types:")
            result = session.run("""
                MATCH ()-[r]->()
                RETURN DISTINCT type(r) as relationship_type, count(*) as count
                ORDER BY count DESC
            """)
            
            relationships_exist = False
            for record in result:
                relationships_exist = True
                print(f"  {record['relationship_type']}: {record['count']}")
            
            if not relationships_exist:
                print("  ❌ NO RELATIONSHIPS FOUND!")
                print("  This explains why IP addresses show as None!")
            
            # Check SecurityAlert relationships specifically
            print("\n📊 SecurityAlert node connections:")
            result = session.run("""
                MATCH (alert:SecurityAlert)
                OPTIONAL MATCH (alert)-[r]-(other)
                RETURN alert.attack_type, type(r) as relationship_type, labels(other) as connected_labels, count(r) as connection_count
                LIMIT 5
            """)
            
            for record in result:
                print(f"  {record['alert.attack_type']}: {record['relationship_type']} -> {record['connected_labels']} (count: {record['connection_count']})")
            
            # Check if SecurityAlert has any relationships at all
            print("\n📊 Do SecurityAlerts have ANY relationships?")
            result = session.run("""
                MATCH (alert:SecurityAlert)
                OPTIONAL MATCH (alert)-[r]-()
                RETURN alert.attack_type, count(r) as total_relationships
                LIMIT 5
            """)
            
            for record in result:
                print(f"  {record['alert.attack_type']}: {record['total_relationships']} relationships")
            
            # Check NetworkLog relationships
            print("\n📊 NetworkLog node connections:")
            result = session.run("""
                MATCH (log:NetworkLog)
                OPTIONAL MATCH (log)-[r]-(other)
                RETURN log.protocol, type(r) as relationship_type, labels(other) as connected_labels, count(r) as connection_count
                LIMIT 5
            """)
            
            for record in result:
                print(f"  {record['log.protocol']}: {record['relationship_type']} -> {record['connected_labels']} (count: {record['connection_count']})")
            
            # Check if there are isolated IPAddress nodes
            print("\n📊 IPAddress nodes status:")
            result = session.run("""
                MATCH (ip:IPAddress)
                OPTIONAL MATCH (ip)-[r]-()
                RETURN ip.address, count(r) as relationships_count
                ORDER BY relationships_count DESC
                LIMIT 10
            """)
            
            for record in result:
                print(f"  IP {record['ip.address']}: {record['relationships_count']} relationships")
            
            # Check if the problem is in how IPs are stored
            print("\n📊 Sample IP addresses in database:")
            result = session.run("""
                MATCH (ip:IPAddress)
                RETURN ip.address
                LIMIT 10
            """)
            
            ip_addresses = [record['ip.address'] for record in result]
            print(f"  IP addresses found: {ip_addresses}")
            
            # Check if SecurityAlerts contain IP info as properties instead
            print("\n📊 Do SecurityAlerts have IP properties directly?")
            result = session.run("""
                MATCH (alert:SecurityAlert)
                RETURN keys(alert) as properties
                LIMIT 1
            """)
            
            for record in result:
                properties = record['properties']
                ip_props = [p for p in properties if 'ip' in p.lower() or 'source' in p.lower() or 'destination' in p.lower()]
                print(f"  IP-related properties: {ip_props}")
                
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    check_relationships()