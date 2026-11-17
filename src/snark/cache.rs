// process-wide cache of row width and r1cs matrices, keyed by (domain tag, shape_key)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::r1cs::{self, R1cs};
use super::spartan::spark::{self, SparkKey};
use super::{choose_width, Layout};
use crate::circuits::CommittedRelation;
use crate::error::Result;

#[derive(Clone, Debug)]
pub struct CachedShape {
    pub width: usize,
    pub r1cs: Arc<R1cs>,
}

type Key = (&'static [u8], Vec<usize>);

fn cache() -> &'static Mutex<HashMap<Key, CachedShape>> {
    static C: OnceLock<Mutex<HashMap<Key, CachedShape>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

// (W, matrices) for statements shaped like stmt, synthesized on first use
pub fn shape<Rel: CommittedRelation>(stmt: &Rel::Statement) -> Result<CachedShape> {
    let key: Key = (Rel::DOMAIN, Rel::shape_key(stmt));
    if let Some(hit) = cache().lock().expect("cache poisoned").get(&key) {
        return Ok(hit.clone());
    }
    // synthesize outside the lock
    let width = choose_width::<Rel>(stmt)?;
    let r1cs = Arc::new(r1cs::relation_shape::<Rel>(stmt, width)?);
    let entry = CachedShape { width, r1cs };
    cache().lock().expect("cache poisoned").insert(key, entry.clone());
    Ok(entry)
}

// spark computation commitment for this shape, encoded once
pub fn spark_key<Rel: CommittedRelation>(stmt: &Rel::Statement) -> Result<Arc<SparkKey>> {
    static K: OnceLock<Mutex<HashMap<Key, Arc<SparkKey>>>> = OnceLock::new();
    let map = K.get_or_init(|| Mutex::new(HashMap::new()));
    let key: Key = (Rel::DOMAIN, Rel::shape_key(stmt));
    if let Some(hit) = map.lock().expect("cache poisoned").get(&key) {
        return Ok(hit.clone());
    }
    let _span = tracing::info_span!("spark_preprocess", relation = Rel::NAME).entered();
    let s = shape::<Rel>(stmt)?;
    let layout = Layout::new(s.width, s.r1cs.num_wit, s.r1cs.num_inst, Rel::external_rows(stmt).len());
    let k = Arc::new(spark::preprocess(&s.r1cs, &layout));
    map.lock().expect("cache poisoned").insert(key, k.clone());
    Ok(k)
}

pub fn len() -> usize {
    cache().lock().expect("cache poisoned").len()
}
