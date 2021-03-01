# hash
Portable class library containing hashing code

This is a portable class library for the .Net framework. This was originally created specifically so that hashing would be directly available when creating portable programs in Visual Studio. This was useful since creating "portable" programs (ones that would run on iOS, Android, and UWP) meant not being able to access many system functions, including hashing, without creating a class library per-platform. Since this library directly implements functions instead of relying on the underlying OS to provide them, it can be used on any platform that can work with portable class libraries.
