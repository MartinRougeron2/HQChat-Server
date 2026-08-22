# iOS Library Setup Guide

## Step 1: Copy iOS Libraries to Project

Copy the built iOS libraries to your Xcode project:

```bash
# From the project root
cp native/hqc/lib/src/ios_output/libhqc_wrap_ios_device.a apps/apple/
cp native/hqc/lib/src/ios_output/libhqc_wrap_ios_simulator.a apps/apple/
```

## Step 2: Add Libraries to Xcode Project

1. Open `DissQus.xcodeproj` in Xcode
2. Right-click on the project in the navigator
3. Select "Add Files to DissQus..."
4. Navigate to and select:
   - `libhqc_wrap_ios_device.a`
   - `libhqc_wrap_ios_simulator.a`
5. **Important**: Check "Copy items if needed" and select "Create groups"
6. Click "Add"

## Step 3: Configure Conditional Linking

### In Xcode:

1. Select your project in the navigator
2. Select the **DissQus** target
3. Go to **Build Phases** tab
4. Expand **Link Binary With Libraries**

### For `libhqc_wrap.dylib` (macOS only):

1. Find `libhqc_wrap.dylib` in the list
2. Click the **+** button or select it
3. In the right panel, set **Platform Filter** to **macOS**

### For `libhqc_wrap_ios_device.a` (iOS device only):

1. Find `libhqc_wrap_ios_device.a` in the list
2. If not there, click **+** and add it
3. Set **Platform Filter** to **iOS**
4. Set **Architectures** to **arm64** (or leave blank for all iOS architectures)

### For `libhqc_wrap_ios_simulator.a` (iOS simulator only):

1. Find `libhqc_wrap_ios_simulator.a` in the list
2. If not there, click **+** and add it
3. Set **Platform Filter** to **iOS Simulator**

## Step 4: Update Build Settings

1. Select the **DissQus** target
2. Go to **Build Settings** tab
3. Search for **"Other Linker Flags"**
4. Add platform-specific flags:

### For iOS Device:

- Add condition: **Any iOS SDK**
- Value: `-force_load $(PROJECT_DIR)/libhqc_wrap_ios_device.a`

### For iOS Simulator:

- Add condition: **Any iOS Simulator SDK**
- Value: `-force_load $(PROJECT_DIR)/libhqc_wrap_ios_simulator.a`

### For macOS:

- Add condition: **Any macOS SDK**
- Value: `-L$(PROJECT_DIR) -lhqc_wrap`

## Step 5: Update Library Search Paths

1. In **Build Settings**, search for **"Library Search Paths"**
2. Add: `$(PROJECT_DIR)` (should already be there)

## Step 6: Update Bridging Header (if needed)

The bridging header should work for both platforms, but verify:

1. Go to **Build Settings**
2. Search for **"Objective-C Bridging Header"**
3. For iOS: Set to `DissQus/Core/HQC-Bridging-Header.h`
4. For macOS: Set to `DissQus/Core/HQC-Bridging-Header.h`

## Step 7: Verify Header Files

Make sure these header files are accessible:

- `DissQus/Core/HQC-Bridging-Header.h`
- `DissQus/Core/public_wrapper.h` (or wherever it's located)

## Step 8: Test the Build

1. Select **iOS** as the destination
2. Build the project (⌘B)
3. Verify no linking errors
4. Switch to **macOS** destination
5. Build again to ensure macOS still works

## Troubleshooting

### "Undefined symbols" errors:

- Make sure the correct library is linked for the platform
- Check that `-force_load` is used for static libraries on iOS

### "Library not found" errors:

- Verify Library Search Paths include `$(PROJECT_DIR)`
- Check that library files are in the project directory

### "Wrong architecture" errors:

- Ensure device library is used for iOS device builds
- Ensure simulator library is used for iOS simulator builds

