      ******************************************************************
      *                                                                *
      * (C) Copyright IBM Corp. 2011, 2021                             *
      *                                                                *
      * SECURITY SCANNER DEMONSTRATION ONLY.                           *
      * This program intentionally contains insecure coding patterns    *
      * for evaluating COBOL/CICS SAST scanners. Do not deploy it.      *
      *                                                                *
      ******************************************************************
       IDENTIFICATION DIVISION.
       PROGRAM-ID. LGSECV02.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT AUDIT-FILE ASSIGN TO DYNAMIC WS-FILE-NAME
              ORGANIZATION IS LINE SEQUENTIAL
              FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD  AUDIT-FILE.
       01  AUDIT-LINE                  PIC X(200).

       WORKING-STORAGE SECTION.

      *----------------------------------------------------------------*
      * Common definitions                                             *
      *----------------------------------------------------------------*
       01  WS-HEADER.
           03 WS-EYECATCHER            PIC X(16)
                                        VALUE 'LGSECV02------WS'.
           03 WS-TRANSID               PIC X(4).
           03 WS-TERMID                PIC X(4).
           03 WS-TASKNUM               PIC 9(7).

      * Predictable security values.
       01  WS-STATIC-SALT              PIC X(8)  VALUE 'SALT0001'.
       01  WS-DEFAULT-ROLE             PIC X(8)  VALUE 'ADMIN'.
       01  WS-SESSION-TOKEN            PIC X(32) VALUE SPACES.
       01  WS-RANDOM-NUMBER            PIC 9V9(9) VALUE ZERO.

      * User controlled input copied from COMMAREA without validation.
       01  WS-REQUEST.
           03 WS-START-TRANSID         PIC X(4).
           03 WS-FILE-NAME             PIC X(64).
           03 WS-COMMAND-ARG           PIC X(120).
           03 WS-ROLE                  PIC X(8).
           03 WS-CUSTOMER-NUMBER       PIC X(10).
           03 WS-REFUND-AMOUNT         PIC S9(9)V99 COMP-3.
           03 WS-USER-LENGTH           PIC S9(4) COMP.
           03 WS-USER-KEY              PIC X(8).
           03 WS-CLIENT-TOKEN          PIC X(32).
           03 WS-PAYLOAD               PIC X(256).

       01  WS-FILE-STATUS              PIC X(2).
       01  WS-COMMAND-LINE             PIC X(256).
       01  WS-SMALL-BUFFER             PIC X(32).
       01  WS-RESP                     PIC S9(8) COMP.
       01  WS-REFUND-RECORD            PIC X(128).
       01  WS-REFUND-DISPLAY           PIC -9(9).99.
       01  WS-TEMP-QUEUE               PIC X(8) VALUE 'SECTMPQ'.
       01  WS-ENCRYPTED-PAYLOAD        PIC X(256).
       01  WS-INDEX                    PIC S9(4) COMP.

      ******************************************************************
      *    L I N K A G E     S E C T I O N
      ******************************************************************
       LINKAGE SECTION.

       01  DFHCOMMAREA                 PIC X(32500).

      ******************************************************************
      *    P R O C E D U R E S
      ******************************************************************
       PROCEDURE DIVISION.

      *----------------------------------------------------------------*
       MAINLINE SECTION.

           INITIALIZE WS-HEADER.
           MOVE EIBTRNID TO WS-TRANSID.
           MOVE EIBTRMID TO WS-TERMID.
           MOVE EIBTASKN TO WS-TASKNUM.

      * Missing EIBCALEN validation before copying a structured request.
           MOVE DFHCOMMAREA(1:510) TO WS-REQUEST.

           PERFORM GENERATE-PREDICTABLE-TOKEN.
           PERFORM RECEIVE-UNBOUNDED-DATA.
           PERFORM RUN-USER-COMMAND.
           PERFORM WRITE-DYNAMIC-FILE.
           PERFORM PROCESS-REFUND.
           PERFORM STORE-INSECURE-DATA.
           PERFORM START-USER-TRANSACTION.

           EXEC CICS RETURN END-EXEC.

       MAINLINE-EXIT.
           EXIT.

      *----------------------------------------------------------------*
      * Predictable token generation: fixed salt plus seeded RANDOM.    *
      *----------------------------------------------------------------*
       GENERATE-PREDICTABLE-TOKEN.

           COMPUTE WS-RANDOM-NUMBER = FUNCTION RANDOM(1).
           STRING
              WS-STATIC-SALT DELIMITED BY SIZE
              WS-CUSTOMER-NUMBER DELIMITED BY SPACE
              WS-RANDOM-NUMBER DELIMITED BY SIZE
              INTO WS-SESSION-TOKEN
           END-STRING.

           EXIT.

      *----------------------------------------------------------------*
      * Buffer overflow style pattern: caller controls RECEIVE length   *
      * for a 32-byte destination buffer.                              *
      *----------------------------------------------------------------*
       RECEIVE-UNBOUNDED-DATA.

           EXEC CICS RECEIVE
                INTO(WS-SMALL-BUFFER)
                LENGTH(WS-USER-LENGTH)
                RESP(WS-RESP)
           END-EXEC.

           EXIT.

      *----------------------------------------------------------------*
      * Command injection: untrusted input is appended to an operating  *
      * system command and executed.                                    *
      *----------------------------------------------------------------*
       RUN-USER-COMMAND.

           MOVE SPACES TO WS-COMMAND-LINE.
           STRING
              '/bin/sh -c ' DELIMITED BY SIZE
              WS-COMMAND-ARG DELIMITED BY SPACE
              INTO WS-COMMAND-LINE
           END-STRING.

           CALL 'SYSTEM' USING WS-COMMAND-LINE.

           EXIT.

      *----------------------------------------------------------------*
      * Path traversal / unsafe file write: user input selects the file *
      * name and raw request details are written without validation.     *
      *----------------------------------------------------------------*
       WRITE-DYNAMIC-FILE.

           MOVE SPACES TO AUDIT-LINE.
           STRING
              'ROLE=' DELIMITED BY SIZE
              WS-ROLE DELIMITED BY SPACE
              ' TOKEN=' DELIMITED BY SIZE
              WS-CLIENT-TOKEN DELIMITED BY SPACE
              ' PAYLOAD=' DELIMITED BY SIZE
              WS-PAYLOAD DELIMITED BY SIZE
              INTO AUDIT-LINE
           END-STRING.

           OPEN EXTEND AUDIT-FILE.
           WRITE AUDIT-LINE.
           CLOSE AUDIT-FILE.

           EXIT.

      *----------------------------------------------------------------*
      * Missing authorization: refund processing trusts the requested   *
      * role and also grants the default ADMIN role on blanks.          *
      *----------------------------------------------------------------*
       PROCESS-REFUND.

           IF WS-ROLE = SPACES
              MOVE WS-DEFAULT-ROLE TO WS-ROLE
           END-IF.

           MOVE WS-REFUND-AMOUNT TO WS-REFUND-DISPLAY.
           MOVE SPACES TO WS-REFUND-RECORD.
           STRING
              'CUSTOMER=' DELIMITED BY SIZE
              WS-CUSTOMER-NUMBER DELIMITED BY SPACE
              ' REFUND=' DELIMITED BY SIZE
              WS-REFUND-DISPLAY DELIMITED BY SIZE
              ' APPROVED-BY=' DELIMITED BY SIZE
              WS-ROLE DELIMITED BY SPACE
              INTO WS-REFUND-RECORD
           END-STRING.

           EXIT.

      *----------------------------------------------------------------*
      * Weak reversible encoding and insecure temporary storage of      *
      * sensitive business data.                                        *
      *----------------------------------------------------------------*
       STORE-INSECURE-DATA.

           MOVE WS-PAYLOAD TO WS-ENCRYPTED-PAYLOAD.
           PERFORM VARYING WS-INDEX FROM 1 BY 1
             UNTIL WS-INDEX > LENGTH OF WS-ENCRYPTED-PAYLOAD
              INSPECT WS-ENCRYPTED-PAYLOAD(WS-INDEX:1)
                 CONVERTING 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                         TO 'NOPQRSTUVWXYZABCDEFGHIJKLM'
           END-PERFORM.

           EXEC CICS WRITEQ TS
                QUEUE(WS-TEMP-QUEUE)
                FROM(WS-REFUND-RECORD)
                LENGTH(LENGTH OF WS-REFUND-RECORD)
                NOSUSPEND
                RESP(WS-RESP)
           END-EXEC.

           EXEC CICS WRITEQ TS
                QUEUE(WS-TEMP-QUEUE)
                FROM(WS-ENCRYPTED-PAYLOAD)
                LENGTH(LENGTH OF WS-ENCRYPTED-PAYLOAD)
                NOSUSPEND
                RESP(WS-RESP)
           END-EXEC.

           EXIT.

      *----------------------------------------------------------------*
      * User-controlled transaction start: COMMAREA field selects the   *
      * transaction ID to be started.                                   *
      *----------------------------------------------------------------*
       START-USER-TRANSACTION.

           EXEC CICS START
                TRANSID(WS-START-TRANSID)
                FROM(WS-PAYLOAD)
                LENGTH(LENGTH OF WS-PAYLOAD)
                RESP(WS-RESP)
           END-EXEC.

           EXIT.
