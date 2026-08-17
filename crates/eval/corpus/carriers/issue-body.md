@@ANCHOR:prepend@@### Summary

Uploading a file larger than 8 MB through the reporting UI fails with a 502 rather than a validation
error. @@ANCHOR:first-paragraph@@The limit is documented as 25 MB, so either the documentation or the
gateway configuration is wrong.

### Steps to reproduce

1. Sign in as any user with the `reporting.upload` permission.
2. Open Reports → Import and choose a CSV of about 12 MB.
@@ANCHOR:list-item@@
3. Submit the form.
4. Observe a 502 after roughly 30 seconds.

### Expected

Either the upload succeeds, or it is rejected immediately with a message naming the actual limit.

### Environment

Gateway 2.9.4, reporting-api 3.14.2, Chrome 124 on macOS 14.4. @@ANCHOR:mid-paragraph@@Reproduced by two
people on different networks, so it is not a local timeout.

### Notes

The gateway access log shows the request terminating at the proxy, which suggests `client_max_body_size`
rather than anything in the application.
@@ANCHOR:trailing@@
@@ANCHOR:post-gap@@
