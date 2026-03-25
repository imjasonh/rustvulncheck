use hyper::http::Request;

fn main() {
    let req = Request::parse(b"GET / HTTP/1.1\r\n");
    println!("{:?}", req);
}
