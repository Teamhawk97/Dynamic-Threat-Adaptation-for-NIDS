import threading
import requests
import time
import socket
import subprocess
import random
import json

class SwarmManager:
    def __init__(self):
        self.my_ip = socket.gethostbyname(socket.gethostname())
        self.is_leader = False
        self.current_leader_ip = "leader"
        
        ip_parts = self.my_ip.split('.')
        self.subnet_prefix = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
        self.potential_nodes = range(2, 15)
        
        # 🔥 THE PATCH: Zero-Trust Blocklist & Penalty Box
        self.blocked_ips = []
        self.failed_leaders = set() # <-- The Penalty Box
        try:
            attacker_ip = socket.gethostbyname("attacker")
            self.blocked_ips.append(attacker_ip)
            print(f"[SEC] Swarm Manager successfully blocklisted rogue node: {attacker_ip}")
        except Exception:
            pass
            
    def get_leader_url(self):
        return f"http://{self.current_leader_ip}:8000"

    def is_node_alive(self, ip):
        try:
            res = subprocess.run(["ping", "-c", "2", "-W", "2", ip], capture_output=True, text=True)
            return res.returncode == 0
        except FileNotFoundError:
            print(f"[FATAL ERROR] 'ping' is not installed. Cannot see {ip}!")
            return False
        except Exception:
            return False

    def hold_election(self):
        print(f"\n[SWARM] Leader {self.current_leader_ip} is DOWN. Initiating Election...")
        time.sleep(random.uniform(0.5, 2.5)) 
        
        alive_nodes = []
        for octet in self.potential_nodes:
            ip = f"{self.subnet_prefix}{octet}"
            
            # 🔥 Ignore attackers AND ignore Zombie Leaders!
            if ip in self.blocked_ips or ip in self.failed_leaders:
                continue
                
            if self.is_node_alive(ip):
                alive_nodes.append(ip)
                
        alive_nodes.sort()
        
        if not alive_nodes:
            print("[SWARM] I am entirely alone. Assuming emergency Leader role.")
            new_leader = self.my_ip
        else:
            new_leader = alive_nodes[0]
        
        if new_leader == self.my_ip:
            self.is_leader = True
            self.current_leader_ip = self.my_ip
            print(f"[SWARM] I won the election! I am the new Leader ({self.my_ip})")
            
            import uvicorn
            from leader_app import leader_node
            threading.Thread(target=lambda: uvicorn.run(leader_node.app, host="0.0.0.0", port=8000), daemon=True).start()
        else:
            self.current_leader_ip = new_leader
            print(f"[SWARM] Election complete. {new_leader} is the new Leader.")
            
            # ==========================================
            # 🔥 THE FIX: THE GRACE PERIOD
            # ==========================================
            print(f"[SWARM] Giving new leader {new_leader} a 5-second grace period to boot API...")
            time.sleep(5) 
            # ==========================================

    def heartbeat_loop(self, model):
        while True:
            time.sleep(3)
            if self.is_leader:
                continue 

            try:
                res = requests.get(f"{self.get_leader_url()}/health", timeout=2)
                if res.status_code == 200:
                    model_res = requests.get(f"{self.get_leader_url()}/get_global_model", timeout=2)
                    global_classes = model_res.json().get("classes", {})

                    # 2. DOWNWARD SYNC (Leader -> Victim)
                    for label, data in global_classes.items():
                        if not isinstance(data, dict) or "prototype" not in data or "count" not in data:
                            continue
                        if label not in model.classes or model.classes[label]["count"] < data["count"]:
                            model.classes[label] = data
                            model.save("/root/app/model.json")
                            print(f"\n[🛡️ FL-SYNC] Downloaded global immunity for: {label}\n")

                    # 3. UPWARD SYNC (Victim -> Leader Store-and-Forward)
                    for label in list(model.classes.keys()): 
                        data = model.classes[label]
                        if label not in global_classes or data["count"] > global_classes.get(label, {}).get("count", 0):
                            print(f"[⬆️ FL-SYNC] Leader is missing '{label}'. Uploading local immunity...")
                            payload = {
                                "label": label,
                                "prototype": data["prototype"],
                                "container_id": self.my_ip
                            }
                            try:
                                upload_res = requests.post(f"{self.get_leader_url()}/update_global_model", json=payload, timeout=2)
                                
                                if upload_res.status_code == 200:
                                    response_data = upload_res.json()
                                    if response_data.get("status") == "merged":
                                        true_label = response_data.get("true_label")
                                        print(f"[🧲 SYNC] Leader merged our '{label}' into '{true_label}'. Erasing old local name.")
                                        del model.classes[label]
                                        model.save("/root/app/model.json")
                            except Exception:
                                pass 

            except Exception:
                if self.current_leader_ip != "leader" and self.current_leader_ip != self.my_ip:
                    print(f"[🚨 SWARM] Leader {self.current_leader_ip} is a Zombie. Blacklisting!")
                    self.failed_leaders.add(self.current_leader_ip)
                    
                self.hold_election()

swarm = SwarmManager()