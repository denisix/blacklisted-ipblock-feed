const fs = require('fs')
const feeds = require('./feeds.json')

const IPS_MERGE_TO_NETWORK = 5

const log = (...msg) => console.log(new Date().toISOString(), ...msg)
const sleep = ms => new Promise(r => setTimeout(r, ms))

const fetchUrl = async (url, headers = {}, retries = 3) => {
  let timeout
  while(retries-->0) {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 30000)

      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'curl/7.81.0',
          'Accept': 'text/plain, */*',
          'Accept-Encoding': 'gzip, deflate, br',
          'Connection': 'close',
          ...headers
        }
      })
      clearTimeout(timeout)

      if (res.ok) return await res.text()
    } catch (err) {
      if (timeout) clearTimeout(timeout)
      log('fetchUrl', url, 'Error:', err.toString())
    }

    await sleep(1000 * Math.pow(2, 3 - retries))
  }
}

const parseIps = (raw) => {
  const ips = []
  const lines = raw.split('\n').map(l => l.trim())
  const re = /\d+\.\d+\.\d+\.\d+\/?\d*/ 
  for (const line of lines) {
    if (!line || line.startsWith('#') || line.startsWith(';')) continue
    const m = re.exec(line)
    if (m && m[0]) ips.push(m[0])
  }
  return ips.sort()
}

const parseNetwork = (cidr) => {
  const [ip, prefix = '32'] = cidr.split('/')
  if (!ip) return
  const prefixNum = parseInt(prefix, 10)
  const net = ip.split('.').reduce((ipInt, octet) => { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0
  const mask = (0xFFFFFFFF << (32 - prefixNum)) >>> 0
  return { ip, prefix: prefixNum, network: (net & mask) >>> 0 }
}

const deduplicate = (cidrs) => {
  // Step 1: Parse and group by prefix length for hierarchical processing
  const prefixMaps = new Map() // prefix -> Map(network -> bestNetwork)
  
  for (const cidr of cidrs) {
    const parsed = parseNetwork(cidr)
    if (!parsed) continue
    
    if (!prefixMaps.has(parsed.prefix)) {
      prefixMaps.set(parsed.prefix, new Map())
    }
    
    const networkMap = prefixMaps.get(parsed.prefix)
    const existing = networkMap.get(parsed.network)
    if (!existing || parsed.prefix < existing.prefix) {
      networkMap.set(parsed.network, parsed)
    }
  }
  
  // Step 2: Lightning-fast hierarchical filtering using parent network Maps
  const sortedPrefixes = Array.from(prefixMaps.keys()).sort((a, b) => a - b)
  const result = new Map() // network -> best network object
  
  // Pre-calculate masks for parent network lookups
  const masks = new Map()
  for (const prefix of sortedPrefixes) {
    masks.set(prefix, (0xFFFFFFFF << (32 - prefix)) >>> 0)
  }
  
  // Process largest subnets first - they can't be contained in anything
  for (const prefix of sortedPrefixes) {
    const networkMap = prefixMaps.get(prefix)
    
    for (const [network, netObj] of networkMap) {
      // Fast parent check: only look at direct parent prefixes
      let isCovered = false
      
      // Check only smaller prefixes (larger subnets) that could contain this
      for (let parentPrefix = 1; parentPrefix < prefix; parentPrefix++) {
        if (!prefixMaps.has(parentPrefix)) continue
        
        const parentMask = masks.get(parentPrefix)
        const parentNetwork = (network & parentMask) >>> 0
        
        // Check if this exact parent network exists in results
        if (result.has(parentNetwork)) {
          const existing = result.get(parentNetwork)
          if (existing.prefix === parentPrefix) {
            isCovered = true
            break
          }
        }
      }
      
      if (!isCovered) {
        // Keep best network for this network address (smallest prefix wins)
        const existing = result.get(network)
        if (!existing || netObj.prefix < existing.prefix) {
          result.set(network, netObj)
        }
      }
    }
  }
  
  // Step 3: Handle /32 to /24 merging optimization
  const finalNetworks = Array.from(result.values())
  const subnet24Map = new Map()
  const nonIP32 = []
  
  for (const net of finalNetworks) {
    if (net.prefix === 32) {
      const subnet24 = (net.network & 0xFFFFFF00) >>> 0
      if (!subnet24Map.has(subnet24)) {
        subnet24Map.set(subnet24, [])
      }
      subnet24Map.get(subnet24).push(net)
    } else {
      nonIP32.push(net)
    }
  }
  
  // Merge /32 IPs to /24 if enough in same subnet
  for (const [subnet24, ips] of subnet24Map) {
    if (ips.length >= IPS_MERGE_TO_NETWORK) {
      const subnetIp = [ (subnet24 >>> 24) & 0xFF, (subnet24 >>> 16) & 0xFF, (subnet24 >>> 8) & 0xFF, 0 ].join('.')
      nonIP32.push({ ip: subnetIp, prefix: 24, network: subnet24 })
    } else {
      nonIP32.push(...ips)
    }
  }
  
  // Step 4: Final pass to remove any /24 networks that might contain merged /24s
  const cleanupMap = new Map()
  
  for (const net of nonIP32) {
    const existing = cleanupMap.get(net.network)
    
    if (!existing || net.prefix < existing.prefix) {
      cleanupMap.set(net.network, net)
    }
  }
  
  return Array.from(cleanupMap.values())
    .map(net => net.prefix === 32 ? net.ip : `${net.ip}/${net.prefix}`)
}


const run = async () => {

  const t0 = Date.now()

  // fetch feeds
  const ips_all = []
  const feedNames = Object.keys(feeds)
  for(let feedName of feedNames) {
     
    const raw = await fetchUrl(feeds[feedName])
    if (raw) {
      const ips = deduplicate(parseIps(raw))
      
      fs.writeFileSync(`source/${feedName}.txt`, raw, 'utf8')
      fs.writeFileSync(`dist/${feedName}.txt`, ips.join('\n'), 'utf8')
      log('feed', feedName, `saved, ${raw.length} bytes, ${ips.length} entries`)

      ips_all.push(...ips)
    }
  }

  const uniq = deduplicate(ips_all)
  fs.writeFileSync('dist/all.txt', uniq.join('\n'), 'utf8')
  log('total', uniq.length, 'entries saved, spent', ((Date.now() - t0) / 1000).toFixed(2), 'sec')
}

run()
