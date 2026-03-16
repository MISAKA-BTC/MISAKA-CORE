//! In-memory object store.
use std::collections::HashMap;
use misaka_types::object::Object;
use misaka_types::ObjectId;

pub struct ObjectStore {
    objects: HashMap<ObjectId, Object>,
}

impl ObjectStore {
    pub fn new() -> Self { Self { objects: HashMap::new() } }

    pub fn put(&mut self, obj: Object) {
        self.objects.insert(obj.id, obj);
    }

    pub fn get(&self, id: &ObjectId) -> Option<&Object> {
        self.objects.get(id)
    }

    pub fn delete(&mut self, id: &ObjectId) -> bool {
        self.objects.remove(id).is_some()
    }

    pub fn len(&self) -> usize { self.objects.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::object::{Object, OwnerKind};

    #[test]
    fn test_object_store() {
        let mut store = ObjectStore::new();
        let obj = Object {
            id: [0xAA; 32], version: 1, owner_kind: OwnerKind::AddressOwner,
            owner: [0xBB; 20], type_tag: "coin".into(), data: vec![],
        };
        store.put(obj);
        assert!(store.get(&[0xAA; 32]).is_some());
        assert_eq!(store.len(), 1);
    }
}
