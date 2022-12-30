#!/usr/bin/env pwsh

Param (
    # Port number to listen on
    [int] $ListenPort = 11000,
    # Port number to send data to
    [int] $SendPort = 11000,
    # Timeout in milliseconds for sending data
    [int] $SendTimeout = 1000,
    # Timeout in milliseconds for receiving data
    [int] $ReceiveTimeout = 1000,
    # Address to send data to
    [string] $SendAddress = "127.0.0.1",
    # Message to send
    [string] $Message = "Hello",
    # switch to run a server
    [Alias("Server")]
    [switch] $RunServer
)

if ( ($null -ne $ENV:AES_KEY_B64) )
{
    $AesKey = [System.Convert]::FromBase64String($ENV:AES_KEY_B64)
}

class Message {
    [byte[]] $IV
    [byte[]] $HMAC
    [byte[]] $Message

    Message([byte[]]$Message) {
        $this.HMAC = $this.ComputeHMAC($Message)
        $this.IV = New-Object byte[] 16
        $this.Message = $Message
    }

    Message([byte[]]$Message, [System.Security.Cryptography.Aes]$Key) {
        $this.HMAC = New-Object byte[] 32
        $this.IV = New-Object byte[] 16
        $this.Message = New-Object byte[] ($Message.Length - ($this.HMAC.Length + $this.IV.Length))
        $ciphertext = New-Object byte[] ($Message.Length - ($this.HMAC.Length + $this.IV.Length))
        $msgOffset = ($this.HMAC.Length + $this.IV.Length)
        [Array]::Copy($Message, 0,              $this.IV,    0, $this.IV.Length)
        [Array]::Copy($Message, $Key.IV.Length, $this.HMAC,  0, $this.HMAC.Length)
        [Array]::Copy($Message, $msgOffset,     $ciphertext, 0, $Message.Length - $msgOffset)

        $this.Message = $Key.DecryptCBC($ciphertext, $this.IV)

        $computedHMAC = $this.ComputeHMAC($ciphertext)
        $diff = Compare-Object $this.HMAC $computedHMAC
        if ( $diff.Length -ne 0 ) {
            Write-Warning "HMAC Check: FAIL"
            $this.HMAC    | Format-Hex | Out-String | Write-Debug
            $computedHMAC | Format-Hex | Out-String | Write-Debug
        }
    }

    [byte[]]ComputeHMAC([byte[]]$Message) {
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($ENV:HMAC_KEY_B64)
        $computedHMAC = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($message))
        return $computedHMAC
    }

    [byte[]]GetEncoded() {
        return $this.IV + $this.HMAC + $this.Message
    }
    
    [byte[]]GetEncoded([System.Security.Cryptography.Aes]$Key) {
        $this.IV = $Key.IV
        $ciphertext = $Key.EncryptCbc($this.Message, $this.iv)
        $this.HMAC = $this.ComputeHMAC($ciphertext)
        return $this.IV + $this.HMAC + $ciphertext
    }
}

$AES = [System.Security.Cryptography.Aes]::Create()
if ( $null -ne $AesKey )
{
    $AES.GenerateIV()
    $AES.Key = $AesKey
}

$encoder = [system.Text.Encoding]::UTF8

function Invoke-Ping {
    param (
        [System.Net.Sockets.UdpClient] $client
    )

    $sendBytes = $encoder.GetBytes($Message)
    $sendBytes | Format-Hex | Out-String | Write-Debug
    if ($null -ne $aesKey) 
    {
        $sendBytes = [Message]::New($sendBytes).GetEncoded($AES)
    }
    
    # Measure the time it takes to send and receive data
    # Send the message
    $transmittedBytes = $client.Send($sendBytes, $sendBytes.Length, $SendAddress, $SendPort)
    $sendBytes | Format-Hex | Out-String | Write-Debug
    Write-Debug "$sendAddress $sendPort"
    # Check if the message was sent successfully
    if ($transmittedBytes -gt 0)
    {
        $RemoteIpEndPoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    
        try
        {
            # Receive the response message
            $receiveBytes = $client.Receive([ref]$RemoteIpEndPoint);

            # Convert the response message to a string
            $returnData = $encoder.GetString($receiveBytes);
            
            # Check if the response message contains any non-printable characters
            if ( $returnData -cmatch '[^\x20-\x7F]' ) 
            {
                # Found non-printable chars, use base64 to encode.
                $returnData = [Convert]::ToBase64String($receiveBytes)
            }
        }
        catch [System.Exception]
        {
            Write-Debug "Caught exception -> $_"
        }
    }
}

function Start-PingServer {
    param (
        [System.Net.Sockets.UdpClient] $client
    )

    $RemoteIpEndPoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    while ($true) {
        $receiveBytes = $null
        try 
        {
            $receiveBytes = $client.Receive([ref]$RemoteIpEndPoint)
    
            $receiveBytes | Format-Hex | Out-String | Write-Debug
            if ($null -ne $AesKey) 
            {
                $message = [Message]::New($receiveBytes, $AES)
            }
            else
            {
                $message = [Message]::New($receiveBytes)
            }
            $message.Message | Format-Hex | Out-String | Write-Debug
        }
        catch [System.Exception]
        {
            if ("TimedOut" -ne $_.Exception.SocketErrorCode)
            {
                Write-Debug "Caught Receive Exception -> $_"
            }
        }
    
        if ($receiveBytes -gt 0)
        {
            $sendBytes = $encoder.GetBytes($Message)
    
            $sendBytes | Format-Hex | Out-String | Write-Debug

            if ($null -ne $aesKey) 
            {
                $sendBytes = [Message]::New($sendBytes).GetEncoded($AES)
            }
            
            $sendBytes | Format-Hex | Out-String | Write-Debug

            $client.Send($sendBytes, $sendBytes.Length, $RemoteIpEndPoint.Address, $RemoteIpEndPoint.Port) | Write-Debug
    
            $messageData = $encoder.GetString($message.Message);
            if ( $messageData -cmatch '[^\x20-\x7F]' ) {
                # Found non-printable chars, use base64 to encode.
                $messageData = [Convert]::ToBase64String($messageData)
            }
            
            Write-Output "{`"message`":`"$messageData`",`"address`":`"$($RemoteIpEndPoint.Address):$($RemoteIpEndPoint.Port)`"}"

        }
    }
}

try {
    $client = [System.Net.Sockets.UdpClient]::new($ListenPort)
    $client.Client.SendTimeout = $SendTimeout;
    $client.Client.ReceiveTimeout = $ReceiveTimeout;

    if ( $RunServer ) 
    {
        Start-PingServer $client
    }
    else
    {
        Measure-Command { 
            Invoke-Ping $client 
        } | ForEach-Object {
            Write-Output "$(Get-Date): $($_.TotalMilliseconds)ms"
        }
    }
}
finally {
    $client.Close()
}