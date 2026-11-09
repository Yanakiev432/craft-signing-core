#![cfg(windows)]
use std::{env,fs::File,path::PathBuf};
use zip::ZipArchive;
fn main(){
 let source=PathBuf::from(env::args_os().nth(1).expect("Synthetic source path"));
 let root=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").canonicalize().unwrap();
 let actual=source.canonicalize().unwrap();
 assert!(actual.starts_with(&root));
 let mut zip=ZipArchive::new(File::open(actual).unwrap()).unwrap();
 println!("ZIP_ENTRY_COUNT={}",zip.len());
 for i in 0..zip.len(){
  let file=zip.by_index(i).unwrap();
  println!("INDEX={} NAME={:?} SIZE={} CRC={:08X}",i,file.name(),file.size(),file.crc32());
 }
}