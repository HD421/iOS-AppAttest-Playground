import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:device_check/device_check.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:cbor/cbor.dart' as cbor;
import 'package:typed_data/typed_data.dart';

/// DeviceCheck API bridge
/// See the [official documentation](https://developer.apple.com/documentation/devicecheck) for detailed usage.
void main() {
  runApp(new application());
}

class application extends StatefulWidget{
  @override
  _applicationState createState() => new _applicationState();
}

class _applicationState extends State<application>{

  dynamic _result;
  dynamic _result_key;
  dynamic _result_attest;

  @override
  void initState() {
    super.initState();
    _generateToken();
    _generateKey();
  }

  void _generateToken() async {
    if (!(await DCAppAttestService.instance.isSupported())){
      setState(() => _result = 'Not supported');
    }

    try { // DeviceCheck token generation, used to verify Device integrity (not related to AppAttest)
      Uint8List token = await DCDevice.instance.generateToken();
      setState(() => _result = base64Encode(token));
    } on PlatformException catch (e) {
      setState(
          () => _result = 'Error: ${e.code} | ${e.details} | ${e.code} | ${e.stacktrace}');
    }
  }

  void _generateKey() async { // AppAttest key generation, used to verify App integrity
    if (!(await DCAppAttestService.instance.isSupported())){
      setState(() => _result_key = 'Not supported');
    }

    try {
      String key = await DCAppAttestService.instance.generateKey();
      setState(() => _result_key = key);
    } on PlatformException catch (e) {
      setState(
              () => _result_key = 'Error: ${e.code} | ${e.details} | ${e.code} | ${e.stacktrace}');
    }
  }

  void _attestKey() async {
    final inst = cbor.Cbor(); //CBOR instance for AttestationObject or AssertionObject decoding

    if (!(await DCAppAttestService.instance.isSupported())){
      setState(() => _result_attest = 'Not supported');
    }

    try {
      String keyId = await DCAppAttestService.instance.generateKey();
      List<int> junk_data = [1, 3, 3, 7]; //Should be SHA256 hash of a unique, single-use data block that embeds a challenge from your server
      Uint8List clientDataHash = Uint8List.fromList(junk_data);
      Uint8List attestationResult = await DCAppAttestService.instance.attestKey(keyId: keyId, clientDataHash: clientDataHash);
      setState(() => _result_attest = base64Encode(attestationResult));

      var list = new List.from(attestationResult).cast<int>();
      inst.decodeFromList(list);
      print(inst.decodedToJSON()); //Decoded CBOR object. Output to console
      //print(inst.decodedPrettyPrint());
    } on PlatformException catch (e) {
      setState(
              () => _result_key = 'Error: ${e.code} | ${e.details} | ${e.code} | ${e.stacktrace}');
    }
  }

  //GUI
  @override
  Widget build(BuildContext context) {
    return new MaterialApp(
      title: "Stateful Widget",
      home: new Scaffold(
        appBar: AppBar(
          title: Text('iOS App Attest Test'),
        ),
        body: SafeArea(
          child: Column(
            children: [
              Expanded(
                  flex: 1,
                  child: Container(
                    decoration: BoxDecoration(border: Border.all()),
                    margin: EdgeInsets.all(4),
                    padding: EdgeInsets.all(4),
                    child: SingleChildScrollView(
                      child: Text('${_result_key ?? ''}'),
                    ),
                ),
              ),
              Flexible(
                  flex: 2,
                  child: ElevatedButton(
                    child: Text('generateKey'), //Part of AppAttest
                    onPressed: _generateKey,
                ),
              ),
              Expanded(
                flex: 2,
                child: Container(
                  decoration: BoxDecoration(border: Border.all()),
                  margin: EdgeInsets.all(4),
                  padding: EdgeInsets.all(4),
                  child: SingleChildScrollView(
                    child: Text('${_result ?? ''}'),
                  ),
                ),
              ),
          Flexible(
            flex: 2,
            child: ElevatedButton(
              child: Text('generateToken'), //Part of DeviceCheck 
              onPressed: _generateToken,
                ),
              ),
              Expanded(
                flex: 2,
                child: Container(
                  decoration: BoxDecoration(border: Border.all()),
                  margin: EdgeInsets.all(4),
                  padding: EdgeInsets.all(4),
                  child: SingleChildScrollView(
                    child: Text('${_result_attest ?? ''}'),
                  ),
                ),
              ),
              Flexible(
                flex: 2,
                child: ElevatedButton(
                  child: Text('attestKey'), //Part of AppAttest
                  onPressed: _attestKey,
                ),
              ),
            ],
          ),
        ),
      )
    );
  }
}