using System;
using System.Runtime.InteropServices;
public static class ClaudeGuardBackdrop {
 [StructLayout(LayoutKind.Sequential)] struct Margins { public int Left, Right, Top, Bottom; }
 [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr h, int a, ref int v, int n);
 [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(IntPtr h, int a, out int v, int n);
 [DllImport("dwmapi.dll")] static extern int DwmExtendFrameIntoClientArea(IntPtr h, ref Margins m);
 [DllImport("dwmapi.dll")] static extern int DwmIsCompositionEnabled(out bool enabled);
 [StructLayout(LayoutKind.Sequential)] struct Rect { public int Left, Top, Right, Bottom; }
 [DllImport("user32.dll",SetLastError=true)] static extern bool GetWindowRect(IntPtr h,out Rect r);
 [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr h);
 [DllImport("user32.dll",SetLastError=true)] static extern int SetWindowRgn(IntPtr h,IntPtr region,bool redraw);
 [DllImport("user32.dll")] static extern int GetWindowRgn(IntPtr h,IntPtr region);
 [DllImport("gdi32.dll")] static extern IntPtr CreateRoundRectRgn(int left,int top,int right,int bottom,int ellipseWidth,int ellipseHeight);
 [DllImport("gdi32.dll")] static extern IntPtr CreateRectRgn(int left,int top,int right,int bottom);
 [DllImport("gdi32.dll")] static extern bool PtInRegion(IntPtr region,int x,int y);
 [DllImport("gdi32.dll")] static extern bool EqualRgn(IntPtr first,IntPtr second);
 [DllImport("user32.dll")] static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
 [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr value);
 static bool IsRoundedMask(IntPtr region,int width,int height,int radius) {
  return !PtInRegion(region,0,0) && !PtInRegion(region,width-1,0) &&
   !PtInRegion(region,0,height-1) && !PtInRegion(region,width-1,height-1) &&
   PtInRegion(region,width/2,0) && PtInRegion(region,0,height/2) &&
   PtInRegion(region,width/2,height/2) && PtInRegion(region,radius,radius);
 }
 public static bool VerifyMaskGeometry(int width,int height,int radius) {
  IntPtr region=CreateRoundRectRgn(0,0,width+1,height+1,radius*2,radius*2);
  if(region==IntPtr.Zero)return false;
  try{return IsRoundedMask(region,width,height,radius);}finally{DeleteObject(region);}
 }
 public static int[] InspectCorners(IntPtr h,int logicalRadius,bool maximized) {
  IntPtr context=SetThreadDpiAwarenessContext(new IntPtr(-4));
  try{
   Rect bounds;if(!GetWindowRect(h,out bounds))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   int width=bounds.Right-bounds.Left,height=bounds.Bottom-bounds.Top,dpi=(int)GetDpiForWindow(h);if(dpi==0)dpi=96;
   int radius=maximized?0:(int)Math.Round(logicalRadius*dpi/96.0);
   IntPtr observed=CreateRectRgn(0,0,0,0),expected=CreateRoundRectRgn(0,0,width+1,height+1,radius*2,radius*2);int kind=0;bool verified=false,exact=false;int inset=-1;
   try{
    kind=GetWindowRgn(h,observed);
    verified=maximized ? (kind==0 || (PtInRegion(observed,0,0) && PtInRegion(observed,width-1,0))) : kind!=0 && IsRoundedMask(observed,width,height,radius);
    exact=kind!=0 && EqualRgn(observed,expected);
    for(int x=0;x<width/2;x++){if(PtInRegion(observed,x,0)){inset=x;break;}}
   }finally{DeleteObject(observed);DeleteObject(expected);}
   return new int[]{kind,width,height,dpi,radius,verified?1:0,exact?1:0,inset};
  }finally{if(context!=IntPtr.Zero)SetThreadDpiAwarenessContext(context);}
 }
 public static int[] SynchronizeCorners(IntPtr h,int logicalRadius,bool maximized) {
  Rect bounds;if(!GetWindowRect(h,out bounds))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  int width=bounds.Right-bounds.Left,height=bounds.Bottom-bounds.Top;
  int dpi=(int)GetDpiForWindow(h);if(dpi==0)dpi=96;
  int radius=maximized?0:(int)Math.Round(logicalRadius*dpi/96.0);
  if(maximized){
   int cleared=SetWindowRgn(h,IntPtr.Zero,true);
   return new int[]{cleared!=0?1:0,width,height,dpi,0,cleared!=0?1:0};
  }
  IntPtr region=CreateRoundRectRgn(0,0,width+1,height+1,radius*2,radius*2);
  if(region==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  int applied=SetWindowRgn(h,region,true);
  // On success Windows owns the region; only delete our allocation on failure.
  if(applied==0){DeleteObject(region);throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
  IntPtr observed=CreateRectRgn(0,0,0,0);bool verified=false;
  try{verified=GetWindowRgn(h,observed)!=0 && IsRoundedMask(observed,width,height,radius);}finally{DeleteObject(observed);}
  return new int[]{1,width,height,dpi,radius,verified?1:0};
 }
 [DllImport("user32.dll",EntryPoint="GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr(IntPtr h,int index);
 public static int[] InspectSurfaceMode(IntPtr h) {
  int mode=0;int hr=DwmGetWindowAttribute(h,38,out mode,4);
  long style=GetWindowLongPtr(h,-20).ToInt64();
  return new int[]{hr,mode,(style & 0x80000L)!=0?1:0};
 }
 public static int[] Apply(IntPtr h) {
  int dark=1, rounded=1, acrylic=1, observed=0; bool composition;
  DwmIsCompositionEnabled(out composition);
  DwmSetWindowAttribute(h,20,ref dark,4); DwmSetWindowAttribute(h,33,ref rounded,4);
  Margins m=new Margins {Left=0,Right=0,Top=0,Bottom=0};
  int frame=DwmExtendFrameIntoClientArea(h,ref m);
  int set=DwmSetWindowAttribute(h,38,ref acrylic,4);
  int read=DwmGetWindowAttribute(h,38,out observed,4);
  return new int[] {set,read,observed,frame,composition?1:0};
 }
}