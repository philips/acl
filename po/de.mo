��    $      <  5   \  C   0  l  t  �  �  B   �  l  �  �   i	  �   �	  Z   w
     �
     �
             '   &  '   N     v  $   �     �  &   �  /   �  0   '  +   X  3   �  =   �     �  %     2   7     j     �     �     �     �  "   �     �        /     %   J  :   p  v  �  �  "  4     ~  7  u   �  �   ,  [   �     	      "     C     R  5   i  3   �      �  '   �       3   4  5   h  8   �  2   �  :   
  E   E     �  "   �  3   �                +     B     a  *   t     �     �  0   �  &   �                   "                                             	                                     !         
          #                            $                                     --mask              do recalculate the effective rights mask
   -R, --recursive         recurse into subdirectories
      --post-order        visit subdirectories first
  -L, --logical           logical walk, follow symbolic links
  -P, --physical          physical walk, do not follow symbolic links
      --restore=file      restore ACLs (inverse of `getfacl -R')
      --test              test mode (ACLs are not modified)
   -a, --access            display the file access control list only
  -d, --default           display the default access control list only
      --omit-header       do not display the comment header
      --all-effective     print all effective rights
      --no-effective      print no effective rights
      --skip-base         skip files that only have the base entries
  -R, --recursive         recurse into subdirectories
      --post-order        visit subdirectories first
  -L, --logical           logical walk, follow symbolic links
  -P  --physical          physical walk, do not follow symbolic links
      --tabular           use tabular output format
      --absolute-names    don't strip leading '/' in pathnames
   -d, --default           display the default access control list
   -m, --modify=acl        modify the current ACL(s) of file(s)
  -M, --modify-file=file  read ACL entries to modify from file
  -x, --remove=acl        remove entries from the ACL(s) of file(s)
  -X, --remove-file=file  read ACL entries to remove from file
  -b, --remove-all        remove all extended ACL entries
  -k, --remove-default    remove the default ACL
   -n, --no-mask           don't recalculate the effective rights mask
  -d, --default           operations apply to the default ACL
   -s, --set=acl           set the ACL of file(s), replacing the current ACL
  -S, --set-file=file     read ACL entries to set from file
   -v, --version           print version and exit
  -h, --help              this help text
 # (acl unchanged)
 # (default acl unchanged)
 # (empty acl)
 # (empty default acl)
 %s %s -- get file access control lists
 %s %s -- set file access control lists
 %s: %s in line %d of file %s
 %s: %s in line %d of standard input
 %s: %s: %s in line %d
 %s: %s: Cannot change owner/group: %s
 %s: %s: No filename found in line %d, aborting
 %s: %s: Only directories can have a default ACL
 %s: %s: Resulting ACL `%s': %s at entry %d
 %s: %s: Resulting default ACL `%s': %s at entry %d
 %s: No filename found in line %d of standard input, aborting
 %s: Option -%c incomplete
 %s: Option -%c: %s near character %d
 %s: Removing leading '/' from absolute path names
 %s: Standard input: %s
 Duplicate entries Invalid entry type Missing or wrong entry Multiple entries Try `%s -h' for more information.
 Usage: %s %s
 Usage: %s [-%s] file ...
 [-bkndRLPvh] { -s|-S|-m|-M|-x|-X ... } file ... [-bkndvh] {-m|-M|-x|-X ... } file ...       --mask               Effektive Rechte neu berechnen
   -R, --recursive          In Unterverzeichnisse wechseln
      --post-order         Unterverzeichnisse zuerst besuchen
  -L, --logical            Symbolischen Links folgen
  -P, --physical           Symbolischen Links nicht folgen
      --restore=datei      ACLs wiederherstellen (Umkehr von `getfacl -R')
      --test               Testmodus (ACLs werden nicht ver�ndert)
   -a, --access             Nur die ACL ausgeben
  -d, --default            Nur die Default-ACL ausgeben
      --omit-header        Keine Datei-Kommentare ausgeben
      --all-effective      Alle Effektivrechte-Kommentare ausgeben
      --no-effective       Keine Effektivrechte-Kommentare ausgeben
      --skip-base          �berspringe Dateien mit Basiseintr�gen
  -R, --recursive          In Unterverzeichnisse wechseln
      --post-order         Unterverzeichnisse zuerst besuchen
  -L, --logical            Symbolische Links verfolgen
  -P, --physical           Symbolische Links nicht verfolgen
      --tabular            Tabellarisches Ausgabeformat verwenden
      --absolute-names     F�hrende '/' in Pfadnamen nicht entfernen
   -d, --default            Die Default-ACL ausgeben
   -m, --modify=acl         Ver�ndere die ACL(s) von Dazei(en)
  -M, --modify-file=datei  Lies die ACL-Eintr�ge aus der Datei file
  -x, --remove=acl         Entferne Eintr�ge aus ACLs von Datei(en)
  -X, --remove-file=datei  Lies die ACL-Eintr�ge aus der Datei file
  -b, --remove-all         Alle erweiterten ACL-Eintr�ge entfernen
  -k, --remove-default     Default-ACL entfernen
       --mask               Effektive Rechte nicht neu berechnen
  -d, --default            Bearbeite die Default-ACL
   -s, --set=acl            Ersetze die ACL(s) von Datei(en)
  -S, --set-file=datei     Lies die ACL-Eintr�ge aus der Datei file
   -v, --version            Nur die Version ausgeben
  -h, --help               Diese Hilfe
 # (ACL nicht ver�ndert)
 # (Default-ACL nicht ver�ndert)
 # (leere ACL)
 # (leere Default-ACL)
 %s %s -- Datei-Zugriffskontrollisten (ACLs) anzeigen
 %s %s -- Datei-Zugriffskontrollisten (ACLs) �ndern
 %s: %s in Zeile %d der Datei %s
 %s: %s in Zeile %d der Standardeingabe
 %s: %s: %s in Zeile %d
 %s: %s: Kann Besitzer oder Gruppe nicht �ndern: %s
 %s: %s: Kein Dateiname gefunden in Zeile %d; Abbruch
 %s: %s: Nur Verzeichnisse k�nnen eine Default-ACL haben
 %s: %s: Resultierende ACL `%s': %s bei Eintrag %d
 %s: %s: Resultierende Default-ACL `%s': %s bei Eintrag %d
 %s: Kein Dateiname gefunden in Zeile %d der Standardeingabe; Abbruch
 %s: Option -%c unvollst�ndig
 %s: Option -%c: %s bei Zeichen %d
 %s: Entferne f�hrenden '/' von absoluten Pfadnamen
 %s: Standardeingabe: %s
 Doppelte Eintr�ge Ung�ltiger Eintragstyp Fehlende oder falsche Eintr�ge Mehrfache Eintr�ge Weiterf�hrende Informationen mit `%s -h'.
 Verwendung: %s %s
 Aufruf: %s [-%s] datei ...
 [-bkndRLPvh] { -s|-S|-m|-M|-x|-X ... } datei ... [-bkndvh] {-m|-M|-x|-X ... } datei ... 