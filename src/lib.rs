//! NattoWok Scanner: a privacy-first network scanner that explains what it
//! finds. Everything runs locally; nothing leaves your network.

pub mod dns;
pub mod doctor;
pub mod http;
pub mod identify;
pub mod matching;
pub mod mdns;
pub mod model;
pub mod neighbors;
pub mod netbios;
pub mod netinfo;
pub mod notify;
pub mod oui;
pub mod probe;
pub mod report;
pub mod scan;
pub mod security;
pub mod service;
pub mod settings;
pub mod ssdp;
pub mod store;
pub mod upnp;
pub mod web;
pub mod wol;
