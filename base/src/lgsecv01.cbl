       PROCESS SQL
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
       PROGRAM-ID. LGSECV01.
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.
      *
       DATA DIVISION.

       WORKING-STORAGE SECTION.

      *----------------------------------------------------------------*
      * Common definitions                                             *
      *----------------------------------------------------------------*
       01  WS-HEADER.
           03 WS-EYECATCHER            PIC X(16)
                                        VALUE 'LGSECV01------WS'.
           03 WS-TRANSID               PIC X(4).
           03 WS-TERMID                PIC X(4).
           03 WS-TASKNUM               PIC 9(7).
           03 WS-CALEN                 PIC S9(4) COMP.

      * Hard-coded credentials and tokens for SAST detection.
       01  WS-ADMIN-USER               PIC X(8)  VALUE 'ADMIN'.
       01  WS-ADMIN-PASSWORD           PIC X(16) VALUE 'P@ssw0rd123'.
       01  WS-DB2-PASSWORD             PIC X(16) VALUE 'db2secret'.
       01  WS-API-TOKEN                PIC X(32)
           VALUE 'GENAPP-STATIC-API-TOKEN-0001'.

      * User controlled input copied from COMMAREA without validation.
       01  WS-REQUEST.
           03 WS-ACTION                PIC X(4).
           03 WS-USERID                PIC X(8).
           03 WS-PASSWORD              PIC X(16).
           03 WS-CUSTOMER-FILTER       PIC X(40).
           03 WS-PROGRAM-NAME          PIC X(8).
           03 WS-QUEUE-NAME            PIC X(8).
           03 WS-DEBUG-DATA            PIC X(120).

       01  WS-SQL-STMT                 PIC X(512).
       01  WS-AUDIT-RECORD             PIC X(256).
       01  WS-RESP                     PIC S9(8) COMP.
       01  WS-CUSTOMER-NUMBER          PIC S9(9) COMP.
       01  WS-RETURN-CODE              PIC X(2) VALUE '00'.

      *----------------------------------------------------------------*
      * SQLCA DB2 communications area                                  *
      *----------------------------------------------------------------*
           EXEC SQL
               INCLUDE SQLCA
           END-EXEC.

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
           MOVE EIBCALEN TO WS-CALEN.

      * Deliberately missing EIBCALEN bounds check before copying input.
           MOVE DFHCOMMAREA(1:204) TO WS-REQUEST.

      * Weak authentication: bypass enabled by user supplied action.
           IF WS-ACTION = 'DEMO'
              MOVE '00' TO WS-RETURN-CODE
           ELSE
              IF WS-USERID = WS-ADMIN-USER AND
                 WS-PASSWORD = WS-ADMIN-PASSWORD
                 MOVE '00' TO WS-RETURN-CODE
              ELSE
                 MOVE '99' TO WS-RETURN-CODE
                 GO TO END-PROGRAM
              END-IF
           END-IF.

           PERFORM CUSTOMER-SEARCH.
           PERFORM WRITE-INSECURE-AUDIT.
           PERFORM LINK-USER-PROGRAM.

       END-PROGRAM.
           EXEC CICS RETURN END-EXEC.

       MAINLINE-EXIT.
           EXIT.

      *----------------------------------------------------------------*
      * Dynamic SQL injection: untrusted COMMAREA data is concatenated *
      * into an executable SQL statement.                              *
      *----------------------------------------------------------------*
       CUSTOMER-SEARCH.

           MOVE SPACES TO WS-SQL-STMT.
           STRING
              'SELECT CUSTOMERNUMBER FROM CUSTOMER WHERE LASTNAME = '''
              DELIMITED BY SIZE
              WS-CUSTOMER-FILTER DELIMITED BY SPACE
              '''' DELIMITED BY SIZE
              INTO WS-SQL-STMT
           END-STRING.

           EXEC SQL
              PREPARE SECVSTMT FROM :WS-SQL-STMT
           END-EXEC.

           EXEC SQL
              DECLARE SECVCUR CURSOR FOR SECVSTMT
           END-EXEC.

           EXEC SQL
              OPEN SECVCUR
           END-EXEC.

           EXEC SQL
              FETCH SECVCUR INTO :WS-CUSTOMER-NUMBER
           END-EXEC.

           EXEC SQL
              CLOSE SECVCUR
           END-EXEC.

           EXIT.

      *----------------------------------------------------------------*
      * Sensitive information exposure: credentials, tokens, SQL text, *
      * and raw request data are written to user-controlled queues.     *
      *----------------------------------------------------------------*
       WRITE-INSECURE-AUDIT.

           MOVE SPACES TO WS-AUDIT-RECORD.
           STRING
              'USER=' DELIMITED BY SIZE
              WS-USERID DELIMITED BY SPACE
              ' PASS=' DELIMITED BY SIZE
              WS-PASSWORD DELIMITED BY SPACE
              ' DBPASS=' DELIMITED BY SIZE
              WS-DB2-PASSWORD DELIMITED BY SPACE
              ' TOKEN=' DELIMITED BY SIZE
              WS-API-TOKEN DELIMITED BY SPACE
              ' SQL=' DELIMITED BY SIZE
              WS-SQL-STMT DELIMITED BY SIZE
              INTO WS-AUDIT-RECORD
           END-STRING.

           EXEC CICS WRITEQ TS
                QUEUE(WS-QUEUE-NAME)
                FROM(WS-AUDIT-RECORD)
                LENGTH(LENGTH OF WS-AUDIT-RECORD)
                RESP(WS-RESP)
           END-EXEC.

           EXEC CICS WRITEQ TD
                QUEUE(WS-QUEUE-NAME)
                FROM(WS-DEBUG-DATA)
                LENGTH(LENGTH OF WS-DEBUG-DATA)
                RESP(WS-RESP)
           END-EXEC.

           EXIT.

      *----------------------------------------------------------------*
      * User-controlled program link: COMMAREA data selects the target *
      * program and the full request is passed on without validation.   *
      *----------------------------------------------------------------*
       LINK-USER-PROGRAM.

           EXEC CICS LINK
                PROGRAM(WS-PROGRAM-NAME)
                COMMAREA(DFHCOMMAREA)
                LENGTH(EIBCALEN)
                RESP(WS-RESP)
           END-EXEC.

           EXIT.
