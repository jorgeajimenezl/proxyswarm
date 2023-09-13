use std::net::IpAddr;
use wildmatch::WildMatch;

use crate::error::Error;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Rule {
    Allow,
    Deny,
    Bypass
}

#[derive(Clone)]
enum EntryData {
    Hostname(WildMatch),
    SubNet { addr: IpAddr, prefix: u8 },
}

#[derive(Clone)]
pub struct Entry {
    rule: Rule,
    data: EntryData,
}

#[derive(Clone)]
pub struct Acl {
    entries: Vec<Entry>,
    default: Rule,
}

fn ip_addr_bit_and(ip: IpAddr, prefix: u8) -> Result<IpAddr, Error> {
    Ok(match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(Error::InvalidAclEntry);
            }
            IpAddr::V4((u32::from(v4) & (((1u32 << prefix) - 1) << (32 - prefix))).into())
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(Error::InvalidAclEntry);
            }
            IpAddr::V6((u128::from(v6) & (((1u128 << prefix) - 1) << (128 - prefix))).into())
        }
    })
}

impl Acl {
    pub fn new(default: Rule) -> Self {
        Self {
            entries: Default::default(),
            default,
        }
    }

    pub fn add(&mut self, host: &str, rule: Rule) -> Result<(), Error> {
        match host.split_once('/') {
            Some((ip, prefix)) => {
                let prefix = prefix.parse::<u8>().map_err(|_| Error::InvalidAclEntry)?;
                self.add_addr(
                    ip.parse::<IpAddr>().map_err(|_| Error::InvalidAclEntry)?,
                    Some(prefix),
                    rule,
                )?;
            }
            None => match host.parse::<IpAddr>() {
                Ok(addr) => self.add_addr(addr, None, rule)?,
                Err(_) => self.entries.push(Entry {
                    rule,
                    data: EntryData::Hostname(WildMatch::new(host)),
                }),
            },
        }
        Ok(())
    }

    pub fn add_addr(
        &mut self,
        addr: impl Into<IpAddr>,
        prefix: Option<u8>,
        rule: Rule,
    ) -> Result<(), Error> {
        let prefix = prefix.unwrap_or(128);
        let addr = ip_addr_bit_and(addr.into(), prefix)?;

        self.entries.push(Entry {
            rule,
            data: EntryData::SubNet { addr, prefix },
        });
        Ok(())
    }

    pub fn match_addr(&self, addr: impl Into<IpAddr>) -> Rule {
        let addr = addr.into();
        // get the last matching rule
        return self
            .entries
            .iter()
            .rev()
            .filter(|e| match &e.data {
                EntryData::Hostname(_) => false,
                EntryData::SubNet { addr: ip, prefix } => {
                    ip_addr_bit_and(addr, *prefix).unwrap() == *ip
                }
            })
            .map(|e| e.rule)
            .next()
            .unwrap_or(self.default);
    }

    pub fn match_hostname(&self, hostname: &str) -> Rule {
        let addr = hostname.parse::<IpAddr>().ok();
        return self
            .entries
            .iter()
            .rev()
            .filter(|e| match &e.data {
                EntryData::Hostname(host) => host.matches(hostname),
                EntryData::SubNet { addr: ip, prefix } if addr.is_some() => {
                    ip_addr_bit_and(addr.unwrap(), *prefix).unwrap() == *ip
                }
                _ => false,
            })
            .map(|e| e.rule)
            .next()
            .unwrap_or(self.default);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn new_acl() {
        let acl = Acl::new(Rule::Allow);
        assert_eq!(acl.entries.len(), 0);
    }

    #[test]
    fn default_rule_1() {
        let mut acl = Acl::new(Rule::Allow);
        acl.add("google.com", Rule::Deny).unwrap();

        assert_eq!(acl.match_hostname("wikipedia.org"), Rule::Allow);
        assert_eq!(acl.match_hostname("google.com"), Rule::Deny);
    }

    #[test]
    fn default_rule_2() {
        let mut acl = Acl::new(Rule::Allow);
        acl.add("*.google.com", Rule::Deny).unwrap();

        assert_eq!(acl.match_hostname("www.google.com"), Rule::Deny);
        assert_eq!(acl.match_hostname("drive.google.com"), Rule::Deny);
        assert_eq!(acl.match_hostname("mail.google.com"), Rule::Deny);
        assert_eq!(acl.match_hostname("photos.google.com"), Rule::Deny);
        assert_eq!(acl.match_hostname("google.com"), Rule::Allow);
    }

    #[test]
    #[should_panic]
    fn wrong_host_1() {
        let mut acl = Acl::new(Rule::Allow);
        acl.add("google.com/1", Rule::Deny).unwrap();
    }

    #[test]
    #[should_panic]
    fn wrong_host_2() {
        let mut acl = Acl::new(Rule::Allow);
        acl.add("127.0.0.1/1a", Rule::Deny).unwrap();
    }

    #[test]
    fn match_subnet_ipv4() {
        let mut acl = Acl::new(Rule::Allow);
        acl.add("127.0.0.1/8", Rule::Deny).unwrap();

        assert_eq!(
            acl.match_addr(IpAddr::from_str("127.0.0.1").unwrap()),
            Rule::Deny
        );
        assert_eq!(
            acl.match_addr(IpAddr::from_str("127.0.1.1").unwrap()),
            Rule::Deny
        );
        assert_eq!(
            acl.match_addr(IpAddr::from_str("127.1.255.1").unwrap()),
            Rule::Deny
        );

        assert_eq!(
            acl.match_addr(IpAddr::from_str("128.0.0.1").unwrap()),
            Rule::Allow
        );
        assert_eq!(
            acl.match_addr(IpAddr::from_str("198.168.0.1").unwrap()),
            Rule::Allow
        );
        assert_eq!(
            acl.match_addr(IpAddr::from_str("200.178.52.6").unwrap()),
            Rule::Allow
        );
    }

    #[test]
    fn match_subnet_ipv6() {
        let mut acl = Acl::new(Rule::Allow);
        acl.add("::1/120", Rule::Deny).unwrap();

        assert_eq!(acl.match_addr(IpAddr::from_str("::1").unwrap()), Rule::Deny);
        assert_eq!(
            acl.match_addr(IpAddr::from_str("::ff").unwrap()),
            Rule::Deny
        );
        assert_eq!(
            acl.match_addr(IpAddr::from_str("::af").unwrap()),
            Rule::Deny
        );

        assert_eq!(
            acl.match_addr(IpAddr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap()),
            Rule::Allow
        );
    }

    #[test]
    fn match_subnet_overlap() {
        let mut acl = Acl::new(Rule::Deny);
        acl.add("100.0.0.0/8", Rule::Allow).unwrap();

        assert_eq!(
            acl.match_addr(IpAddr::from_str("127.0.0.1").unwrap()),
            Rule::Deny
        );
        assert_eq!(
            acl.match_addr(IpAddr::from_str("100.1.15.1").unwrap()),
            Rule::Allow
        );

        acl.add("100.1.0.0/16", Rule::Deny).unwrap();

        assert_eq!(
            acl.match_addr(IpAddr::from_str("100.1.15.1").unwrap()),
            Rule::Deny
        );
    }
}
