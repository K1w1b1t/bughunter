description = [[
HunterOps quick protocol/banner reconnaissance helper.
Use only on authorized targets.
]]

author = "HunterOps"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and (port.number == 80 or port.number == 443 or port.number == 8080)
end

action = function(host, port)
  return string.format("hunterops_nmap_hint target=%s port=%d", host.targetname or host.ip, port.number)
end
