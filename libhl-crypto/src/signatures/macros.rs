macro_rules! zero {
    ($a:ident) => {
        for i in 0..$a.len() {
            $a[i] = 0;
        }
    };
}

macro_rules! array_copy {
    ($src:expr, $dst:expr) => {
        for i in 0..$dst.len() {
            $dst[i] = $src[i];
        }
    };
}
