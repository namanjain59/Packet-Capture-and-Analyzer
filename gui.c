  #include <gtk/gtk.h>
  #include <pthread.h>
  int data_size;
  int count = 0;
  #include "code.c"

  void PrintData (GtkTextIter ei, GtkTextBuffer* buff, unsigned char* data , int Size);

  GtkListStore* lis;
  GtkBuilder* bld;
  void addTodispList(char* s1, char*s2, char*s3, char*s4, char*s5)
  {

      GtkTreeIter iter;
      char s31[10];
      char s41[10];
      sprintf(s31,"%s\0",inet_ntoa(source.sin_addr));
      sprintf(s41,"%s\0",inet_ntoa(dest.sin_addr));

      gtk_list_store_append(lis, &iter);
      gtk_list_store_set(lis, &iter, 0, s1, 1, s31, 2, s41, 3, s4, 4, s5,-1);

  }
  int main(int argc, char *argv[])
  {
      GtkBuilder      *builder;
      GtkWidget       *window;
      unilist = (list**)malloc(2000*sizeof(list*));

      gtk_init(&argc, &argv);

      builder = gtk_builder_new();
      gtk_builder_add_from_file (builder, "gui.glade", NULL);

      window = GTK_WIDGET(gtk_builder_get_object(builder, "main_wind"));
      gtk_builder_connect_signals(builder, NULL);

      g_object_unref(builder);

      gtk_widget_show(window);
      gtk_main();
      bld=builder;
      exit(0);
  }

  void on_liststore1_row_inserted(gpointer *user_data)
  {

  }



  void on_main_wind_destroy()
  {
      gtk_main_quit();
  }

  void on_quit_activate()
  {
    gtk_main_quit();
  }
  int sno = 0; int flag=1;
  char buf[10];

  void* fiun()
  {

      int saddr_size ;
      struct sockaddr saddr;

      printf("Capture Starting...\n");

      int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

      if(sock_raw < 0)
      {
          perror("Socket Error");
          return;
      }

      while(flag)
      {
        unsigned char *buffer = (unsigned char *) malloc(65536); 
          saddr_size = sizeof saddr;
          data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
          {
              printf("Recvfrom error , failed to get packets\n");
              return ;
          }
          node = ProcessPacket(buffer);
          node->size=data_size;
          memset(&source, 0, sizeof(source));
          source.sin_addr.s_addr = node->iph->saddr;

          memset(&dest, 0, sizeof(dest));
          dest.sin_addr.s_addr = node->iph->daddr;
          
        if(strcmp(inet_ntoa(source.sin_addr),"0.0.0.0")!=0 && strcmp(inet_ntoa(source.sin_addr),"127.0.0.1")!=0 )
          {
            node->bufo = buffer;
          addtolist(node);

          sprintf(buf,"%d",++sno);
          node->sno = sno;
          char buf2[10];
          sprintf(buf2,"%d",node->size);

          addTodispList(buf,inet_ntoa(source.sin_addr),inet_ntoa(dest.sin_addr),"IP",buf2);


        }
        else free(buffer);

      }

      close(sock_raw);
      printf("Finished");

      return;
  }

  void on_start_but_clicked(GtkButton *button, gpointer *user_data)
  {
          printf("Started\n");
          flag=1;
      GtkTreeIter iter;
      GtkTreeView *treeview1 = GTK_TREE_VIEW(user_data);
      GtkListStore *liststore1 = GTK_LIST_STORE(gtk_tree_view_get_model(treeview1));
      lis=liststore1;
      pthread_t tid;
      pthread_create(&tid, NULL, fiun, NULL);
      pthread_detach(tid);
  }



  void on_Stop_but_clicked(GtkButton *button, gpointer *user_data)
  {
      flag=0;
      printf("Stopped\n");
  }



  void on_search_but_clicked(GtkButton *button, gpointer *user_data)
  {

  }

  char conv_buff[2000];

  void on_treeview1_row_activated (GtkTreeView *view, GtkTreePath *path,
                          GtkTreeViewColumn *col, gpointer* user_data)
  {
    GtkTreeIter   iter;
    GtkTreeModel *model;

    model = gtk_tree_view_get_model(view);

    if (gtk_tree_model_get_iter(model, &iter, path))
    {
      gchar *name;

      gtk_tree_model_get(model, &iter, 0, &name, -1);

      GtkTextIter ei, ee;
      GtkTextView *textview = GTK_TEXT_VIEW(user_data);
      GtkTextBuffer *buff = gtk_text_view_get_buffer(textview);

      gtk_text_buffer_get_start_iter(buff, &ei);
      gtk_text_buffer_get_end_iter(buff, &ee);
      gtk_text_buffer_delete(buff, &ei, &ee);
      gtk_text_buffer_get_end_iter(buff, &ei);

      list* temp = search(name);
      sprintf(conv_buff,"SNO: %d\n",temp->sno);
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff, "Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", temp->eth->h_source[0] , temp->eth->h_source[1] , temp->eth->h_source[2] , temp->eth->h_source[3] , temp->eth->h_source[4] , temp->eth->h_source[5] );
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", temp->eth->h_dest[0] , temp->eth->h_dest[1] , temp->eth->h_dest[2] , temp->eth->h_dest[3] , temp->eth->h_dest[4] , temp->eth->h_dest[5] );
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      memset(&source, 0, sizeof(source));
      source.sin_addr.s_addr = temp->iph->saddr;

      memset(&dest, 0, sizeof(dest));
      dest.sin_addr.s_addr = temp->iph->daddr;

      sprintf(conv_buff,"\n");
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

      sprintf(conv_buff,"IP Header\n");
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

      sprintf(conv_buff,"   |-IP Version        : %d\n",(unsigned int)temp->iph->version);
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)temp->iph->ihl,((unsigned int)(temp->iph->ihl))*4);
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-Type Of Service   : %d\n",(unsigned int)temp->iph->tos);
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(temp->iph->tot_len));
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-Identification    : %d\n",ntohs(temp->iph->id));
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      //sprintf(conv_buff,logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
      //sprintf(conv_buff,logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
      //sprintf(conv_buff,logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
      sprintf(conv_buff,"   |-TTL      : %d\n",(unsigned int)temp->iph->ttl);
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-Protocol : %d\n",(unsigned int)temp->iph->protocol);
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-Checksum : %d\n",ntohs(temp->iph->check));
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      sprintf(conv_buff,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
      gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

      if(temp->udph != NULL) {
        sprintf(conv_buff,"\nUDP Header\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Source Port      : %d\n" , ntohs(temp->udph->source));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Destination Port : %d\n" , ntohs(temp->udph->dest));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-UDP Length       : %d\n" , ntohs(temp->udph->len));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-UDP Checksum     : %d\n" , ntohs(temp->udph->check));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      }
      if(temp->tcph != NULL) {
        sprintf(conv_buff,"\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"TCP Header\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Source Port      : %u\n",ntohs(temp->tcph->source));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Destination Port : %u\n",ntohs(temp->tcph->dest));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Sequence Number    : %u\n",ntohl(temp->tcph->seq));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Acknowledge Number : %u\n",ntohl(temp->tcph->ack_seq));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)temp->tcph->doff,(unsigned int)temp->tcph->doff*4);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        //sprintf(conv_buff,logfile , "   |-CWR Flag : %d\n",(unsigned int)temp->tcph->cwr);
        //sprintf(conv_buff,logfile , "   |-ECN Flag : %d\n",(unsigned int)temp->tcph->ece);
        sprintf(conv_buff,"   |-Urgent Flag          : %d\n",(unsigned int)temp->tcph->urg);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Acknowledgement Flag : %d\n",(unsigned int)temp->tcph->ack);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Push Flag            : %d\n",(unsigned int)temp->tcph->psh);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Reset Flag           : %d\n",(unsigned int)temp->tcph->rst);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Synchronise Flag     : %d\n",(unsigned int)temp->tcph->syn);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff, "   |-Finish Flag          : %d\n",(unsigned int)temp->tcph->fin);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Window         : %d\n",ntohs(temp->tcph->window));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Checksum       : %d\n",ntohs(temp->tcph->check));
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"   |-Urgent Pointer : %d\n",temp->tcph->urg_ptr);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        sprintf(conv_buff,"\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      }
      if(temp->httph!=NULL)
      {
        sprintf(conv_buff,"HTTP Header and payload -\n\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      int iphdrlen = temp->iph->ihl*4;
      int header_size =  sizeof(struct ethhdr) + iphdrlen + temp->tcph->doff*4;
      PrintData(ei,buff,temp->bufo+header_size, data_size-header_size);
      }
      if(temp->ftph!=NULL)
      {
        sprintf(conv_buff,"FTP Header and payload -\n\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      int iphdrlen = temp->iph->ihl*4;
      int header_size =  sizeof(struct ethhdr) + iphdrlen + temp->tcph->doff*4;
      PrintData(ei,buff,temp->bufo+header_size, data_size-header_size);
      }
      if(temp->dnsh != NULL) {
        sprintf(conv_buff,"\nDNS Headers -\n\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        printDNS(ei, buff, temp);
        int iphdrlen = temp->iph->ihl*4; 
        int header_size;
        if(temp->tcph!=NULL)
        header_size =  sizeof(struct ethhdr) + iphdrlen + temp->tcph->doff*4;
        else
        header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof (temp->udph);
        gtk_text_buffer_get_end_iter(buff, &ei);
        PrintData(ei,buff,temp->bufo+header_size, data_size-header_size);
      }

      g_free(name);
      memset(conv_buff,'\0',sizeof(conv_buff));
    }
  }

  void PrintData (GtkTextIter ei, GtkTextBuffer* buff, unsigned char* data , int Size)
  {
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
      if( i!=0 && i%16==0)  
      {
        sprintf(conv_buff,"         ");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        //printf("         ");
        for(j=i-16 ; j<i ; j++)
        {
          if(data[j]>=32 && data[j]<=128)
          {
            sprintf(conv_buff,"%c",(unsigned char)data[j]);
            gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
          }
          else
          {
            sprintf(conv_buff,".");
            gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
          } 
        }
        sprintf(conv_buff,"\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      }

      if(i%16==0)
      {
        sprintf(conv_buff,"         ");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      } 
        sprintf(conv_buff," %02X",(unsigned int)data[i]);
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

      if( i==Size-1) 
      {
        for(j=0;j<15-i%16;j++)
        {
          sprintf(conv_buff,"         ");
          gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
        }
        sprintf(conv_buff,"         ");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

        for(j=i-i%16 ; j<=i ; j++)
        {
          if(data[j]>=32 && data[j]<=128)
          {
            sprintf(conv_buff,"%c",(unsigned char)data[j]);
            gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
          }
          else
          {
            sprintf(conv_buff,".");
            gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
          }
        }
        sprintf(conv_buff,"\n");
        gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
      }
    }
  }

  void printDNS(GtkTextIter ei, GtkTextBuffer* buff, list* node)
  {
    sprintf(conv_buff,"The response contains : ");
    gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

    sprintf(conv_buff,"\n %d Questions.",ntohs(node->dnsh->q_count));
    gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

    sprintf(conv_buff,"\n %d Answers.",ntohs(node->dnsh->ans_count));
    gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

    sprintf(conv_buff,"\n %d Authoritative Servers.",ntohs(node->dnsh->auth_count));
    gtk_text_buffer_insert(buff, &ei, conv_buff, -1);

    sprintf(conv_buff,"\n %d Additional records.\n\n",ntohs(node->dnsh->add_count));
    gtk_text_buffer_insert(buff, &ei, conv_buff, -1);
  }
