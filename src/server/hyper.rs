use hyper::method::Method as HyperMethod;

use core::Method;

impl From<HyperMethod> for Method {
    fn from(method: HyperMethod) -> Method {
        match method {
            HyperMethod::Connect => Method::Connect,
            HyperMethod::Delete => Method::Delete,
            HyperMethod::Get => Method::Get,
            HyperMethod::Head => Method::Head,
            HyperMethod::Options => Method::Options,
            HyperMethod::Patch => Method::Patch,
            HyperMethod::Post => Method::Post,
            HyperMethod::Put => Method::Put,
            HyperMethod::Trace => Method::Trace,
            HyperMethod::Extension(ref s) => Method::Extension(s.to_string()),
        }
    }
}

impl<'a> From<&'a HyperMethod> for Method {
    fn from(method: &'a HyperMethod) -> Method {
        match method {
            &HyperMethod::Connect => Method::Connect,
            &HyperMethod::Delete => Method::Delete,
            &HyperMethod::Get => Method::Get,
            &HyperMethod::Head => Method::Head,
            &HyperMethod::Options => Method::Options,
            &HyperMethod::Patch => Method::Patch,
            &HyperMethod::Post => Method::Post,
            &HyperMethod::Put => Method::Put,
            &HyperMethod::Trace => Method::Trace,
            &HyperMethod::Extension(ref s) => Method::Extension(s.to_string()),
        }
    }
}

impl From<Method> for HyperMethod {
    fn from(method: Method) -> HyperMethod {
        match method {
            Method::Connect => HyperMethod::Connect,
            Method::Delete => HyperMethod::Delete,
            Method::Get => HyperMethod::Get,
            Method::Head => HyperMethod::Head,
            Method::Options => HyperMethod::Options,
            Method::Patch => HyperMethod::Patch,
            Method::Post => HyperMethod::Post,
            Method::Put => HyperMethod::Put,
            Method::Trace => HyperMethod::Trace,
            Method::Extension(ref s) => HyperMethod::Extension(s.to_string()),
        }
    }
}

impl<'a> From<&'a Method> for HyperMethod {
    fn from(method: &'a Method) -> HyperMethod {
        match method {
            &Method::Connect => HyperMethod::Connect,
            &Method::Delete => HyperMethod::Delete,
            &Method::Get => HyperMethod::Get,
            &Method::Head => HyperMethod::Head,
            &Method::Options => HyperMethod::Options,
            &Method::Patch => HyperMethod::Patch,
            &Method::Post => HyperMethod::Post,
            &Method::Put => HyperMethod::Put,
            &Method::Trace => HyperMethod::Trace,
            &Method::Extension(ref s) => HyperMethod::Extension(s.to_string()),
        }
    }
}
