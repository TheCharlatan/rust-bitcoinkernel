use std::marker::PhantomData;

pub struct Iter<'a, T, P, S, G> {
    parent: P,
    current: usize,
    size_fn: S,
    get_fn: G,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T, P, S, G> Iter<'a, T, P, S, G>
where
    S: Fn(&P) -> usize,
    G: Fn(&P, usize) -> Option<T>,
{
    pub fn new(parent: P, size_fn: S, get_fn: G) -> Self {
        Self {
            parent,
            current: 0,
            size_fn,
            get_fn,
            _phantom: PhantomData,
        }
    }
}

impl<'a, T, P, S, G> Iterator for Iter<'a, T, P, S, G>
where
    S: Fn(&P) -> usize,
    G: Fn(&P, usize) -> Option<T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= (self.size_fn)(&self.parent) {
            return None;
        }

        let item = (self.get_fn)(&self.parent, self.current)?;
        self.current += 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.size_fn)(&self.parent).saturating_sub(self.current);
        (remaining, Some(remaining))
    }
}

impl<'a, T, P, S, G> ExactSizeIterator for Iter<'a, T, P, S, G>
where
    S: Fn(&P) -> usize,
    G: Fn(&P, usize) -> Option<T>,
{
}
