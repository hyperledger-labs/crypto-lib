macro_rules! array_copy {
    ($src:expr, $dst:expr) => {
        for i in 0..$dst.len() {
            $dst[i] = $src[i];
        }
    };
}
