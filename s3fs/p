--- s3fs/s3fs.cpp	2008-08-13 01:01:47.000000000 +0200
+++ ../s3fs/s3fs.cpp	2009-05-26 16:18:19.000000000 +0200
@@ -319,6 +319,7 @@
 static string AWSSecretAccessKey;
 static string host = "http://s3.amazonaws.com";
 static mode_t root_mode = 0;
+static string service_path = "/";
 
 // if .size()==0 then local file cache is disabled
 static string use_cache;
@@ -506,7 +507,7 @@
 int
 get_headers(const char* path, headers_t& meta) {
 
-	string resource(urlEncode("/"+bucket + path));
+	string resource(urlEncode(service_path + bucket + path));
 	string url(host + resource);
 
 	auto_curl curl;
@@ -549,7 +550,7 @@
  */
 int
 get_local_fd(const char* path) {
-	string resource(urlEncode("/"+bucket + path));
+	string resource(urlEncode(service_path + bucket + path));
 	string url(host + resource);
 
 	string baseName = mybasename(path);
@@ -653,7 +654,7 @@
  */
 static int
 put_headers(const char* path, headers_t meta) {
-  string resource = urlEncode("/"+bucket + path);
+  string resource = urlEncode(service_path + bucket + path);
   string url = host + resource;
 
   auto_curl curl;
@@ -708,7 +709,7 @@
  */
 static int
 put_local_fd(const char* path, headers_t meta, int fd) {
-	string resource = urlEncode("/"+bucket + path);
+	string resource = urlEncode(service_path + bucket + path);
 	string url = host + resource;
 
 	struct stat st;
@@ -784,7 +785,7 @@
 		}
 	}
 
-	string resource = urlEncode("/"+bucket + path);
+	string resource = urlEncode(service_path +bucket + path);
 	string url = host + resource;
 
 	auto_curl curl;
@@ -894,7 +895,7 @@
 	// If pathname already exists, or is a symbolic link, this call fails with an EEXIST error.
 	cout << "mknod[path="<< path << "][mode=" << mode << "]" << endl;
 
-	string resource = urlEncode("/"+bucket + path);
+	string resource = urlEncode(service_path + bucket + path);
 	string url = host + resource;
 
 	auto_curl curl;
@@ -927,7 +928,7 @@
 s3fs_mkdir(const char *path, mode_t mode) {
 	cout << "mkdir[path=" << path << "][mode=" << mode << "]" << endl;
 
-	string resource = urlEncode("/"+bucket + path);
+	string resource = urlEncode(service_path + bucket + path);
 	string url = host + resource;
 
 	auto_curl curl;
@@ -960,7 +961,7 @@
 s3fs_unlink(const char *path) {
 	cout << "unlink[path=" << path << "]" << endl;
 
-	string resource = urlEncode("/"+bucket + path);
+	string resource = urlEncode(service_path + bucket + path);
 	string url = host + resource;
 
 	auto_curl curl;
@@ -984,7 +985,7 @@
 s3fs_rmdir(const char *path) {
 	cout << "unlink[path=" << path << "]" << endl;
 
-	string resource = urlEncode("/"+bucket + path);
+	string resource = urlEncode(service_path + bucket + path);
 	string url = host + resource;
 
 	auto_curl curl;
@@ -1233,7 +1234,7 @@
 
 	while (IsTruncated == "true") {
 		string responseText;
-		string resource = urlEncode("/"+bucket); // this is what gets signed
+		string resource = urlEncode(service_path + bucket); // this is what gets signed
 		string query = "delimiter=/&prefix=";
 
 		if (strcmp(path, "/") != 0)
@@ -1309,7 +1310,7 @@
 
 								CURL* curl_handle = alloc_curl_handle();
 
-								string resource = urlEncode("/"+bucket + "/" + Key);
+								string resource = urlEncode(service_path + bucket + "/" + Key);
 								string url = host + resource;
 
 								stuff_t stuff;
@@ -1562,6 +1563,14 @@
 			use_cache = strchr(arg, '=') + 1;
 			return 0;
 		}
+		if (strstr(arg, "host=") != 0) {
+			host = strchr(arg, '=') + 1;
+			return 0;
+	 	}
+		if (strstr(arg, "servicepath=") != 0) {
+			service_path = strchr(arg, '=') + 1;
+			return 0;
+		}
     if (strstr(arg, "connect_timeout=") != 0) {
       connect_timeout = strtol(strchr(arg, '=') + 1, 0, 10);
       return 0;
