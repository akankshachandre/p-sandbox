#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <pwd.h>
#include <glob.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <signal.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <limits.h>
#include <fnmatch.h>

struct config {
    char perm[50];
    char filename[50];
};


struct config *configs;
int lines=0;
DIR *dir;
pid_t child;
char perm[50];
char cwd[1024];

char* getDefaultFile(DIR *dir){

    struct dirent *ent;
    char *filename = NULL;

    while((ent=readdir(dir))!=NULL){
        if(strstr(ent->d_name,"fendrc")!=NULL){
            filename = ent->d_name;
            break;
        }

    }
    return filename;
}

char* getConfigFile(){
    char *filename;

    if (getcwd(cwd, sizeof(cwd)) != NULL){
        dir = opendir(cwd);
        if(dir){
            filename = getDefaultFile(dir);

            if(filename==NULL){
                struct passwd *pwd = getpwuid(getuid());

                const char *homedir = pwd->pw_dir;

                dir = opendir(homedir);

                if(dir){
                    chdir(homedir);
                    filename = getDefaultFile(dir);
                }

            }
        }
    }
    return filename;
}


int getFileSize(char *filename){
    FILE *file;
    file = fopen(filename,"r");

    if(file==NULL){
        return -1;
    }

    int lines = 0;
    char ch;
    while(!feof(file)){
        ch = fgetc(file);
        if(ch == '\n')
            lines++;
    }
    fclose(file);
    return lines;

}

void init_config(struct config *configs,char *filename){

    FILE *fp;
    fp = fopen(filename,"r");
    if(fp==NULL)
        exit(EXIT_FAILURE);

    int i = 0;
    for(i=0;i<lines;i++){
            fscanf(fp,"%s %s",configs[i].perm,configs[i].filename);
        }
    closedir(dir);

}




char* getPermission(char *filename,struct config *configs){
	int i = 0;
	char *filePerm;

	for(i=0;i<lines;i++){
		if(fnmatch(configs[i].filename,filename,FNM_PATHNAME)==0){ 
				filePerm = configs[i].perm;
				return filePerm;
			}
			else{
				filePerm = "999";
			}

	}
		
	return filePerm;
}


char *read_string(pid_t child, unsigned long addr) {
#define INITIAL_ALLOCATION 4096
    char *val = (char *) malloc(INITIAL_ALLOCATION);
    size_t allocated = INITIAL_ALLOCATION;
    size_t read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = (char *) realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL) {
            break;
        }
        read += sizeof tmp;
    }
    return val;
}


char *getRealPath(char* filename){
    char actualpath[PATH_MAX];
    char *ptr;
    ptr = realpath(filename,actualpath);
    return ptr;
}


void killchild(pid_t child,char* program,char* filename){
    kill(child,SIGTERM);
    fprintf(stderr,"Terminating: %s",program);
    fprintf(stderr," unauthorized access to: %s",filename);
    exit(0);
}


void sandb_init(pid_t child,char* firstarg,char *execArgs[]){
    struct user_regs_struct regs;
    int status;
    int insyscall = 0;


    child = fork();

    if(child == -1)
        err(EXIT_FAILURE, "[SANDBOX] Error on fork:");



    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        char actualpath[PATH_MAX];
        char *ptr;
        ptr = realpath(firstarg,actualpath);
        if(ptr!=NULL)
            firstarg = ptr;

        execvp(firstarg, execArgs);
        
    }

    else {
        wait(NULL);

        ptrace(PTRACE_GETREGS,child, NULL,&regs);

        if(regs.orig_rax == SYS_execve){

            char *ptr = getRealPath(firstarg);
            if(ptr!=NULL)
                firstarg = ptr;

            char *origperm = getPermission(firstarg,configs);

            if(origperm[2]=='0'){
                killchild(child,firstarg,firstarg);
            }
        }   

        sandb_run(child,firstarg);
                
    }       

}

void sandb_run(pid_t child,char *firstarg){
    int status;
    struct user_regs_struct regs;
    int insyscall = 0;

    while(1){
        if(ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
            if(errno == ESRCH) {
                waitpid(child, &status, __WALL | WNOHANG);
                killchild(child,errno,errno);
            } else {
                err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
            }
        }

        wait(&status);
        if(WIFEXITED(status))
            break;
        ptrace(PTRACE_GETREGS,child, NULL,&regs);

        if(regs.orig_rax == SYS_open) {
            if(insyscall == 0) {
                insyscall = 1;

                char *argfile = read_string(child,regs.rdi);
                char *ptr = getRealPath(argfile);
                if(ptr!=NULL)
                    argfile = ptr;

                char *origperm = getPermission(argfile,configs);
                regs.rsi = regs.rsi & O_ACCMODE;
                    if(regs.rsi == O_WRONLY){
                            if(origperm[1]=='0')
                                killchild(child,firstarg,argfile);
                            
                    }
                    if(regs.rsi == O_RDONLY){
                            if(origperm[0]=='0')
                               killchild(child,firstarg,argfile);
                    }

            }

            else{
                    insyscall = 0;
            }
        }

        if(regs.orig_rax == SYS_openat){
            if(insyscall == 0) {
                insyscall = 1;
                    
                char *argfile = read_string(child,regs.rsi);
                char *ptr = getRealPath(argfile);
                if(ptr!=NULL)
                    argfile = ptr;


                char *origperm = getPermission(argfile,configs);
                regs.rdx = regs.rdx & O_ACCMODE;
                if(regs.rdx == O_WRONLY){
                    if(origperm[1]=='0')
                        killchild(child,firstarg,argfile);
                }
                if(regs.rdx == O_RDONLY){
                    if(origperm[0]=='0')
                        killchild(child,firstarg,argfile);
                }
            }

            else
                insyscall = 0;
        }

    }
}



int main(int argc,char** argv)
{
    pid_t child;
    int status;
    int insyscall = 0;
    struct user_regs_struct regs;
    char *execArgs[20];
    char *filename =NULL;
    struct config conf;
    int i;
    int j =0;
    char *envArgs = {NULL};
    char *firstarg = NULL;
    char *executable;


    if(argc < 2) {
        errx(EXIT_FAILURE, "[SANDBOX] Usage : %s [-c config.txt] <command [arg1...]>", argv[0]);
    }


    if(strcmp(argv[1],"-c")==0){
        filename = argv[2];
        if(filename==NULL)
            errx(EXIT_FAILURE, "[SANDBOX] Usage : %s [-c config.txt] <command [arg1...]>", argv[0]);
        firstarg = argv[3];
        if(firstarg==NULL)
            errx(EXIT_FAILURE, "[SANDBOX] Usage : %s [-c config.txt] <command [arg1...]>", argv[0]);

        for(i=3;i<argc;i++){
        	execArgs[j] = argv[i];
        	j = j+1;
        }
        execArgs[j] = NULL;
    }

    else{
        filename = getConfigFile();
        firstarg = argv[1];
        if(firstarg==NULL)
            errx(EXIT_FAILURE, "[SANDBOX] Usage : %s [-c config.txt] <command [arg1...]>", argv[0]);
        for(i=1;i<argc;i++){
        	execArgs[j] = argv[i];
        	j = j+1;
        }
        execArgs[j] = NULL;
    }

    if(filename!=NULL){
        lines = getFileSize(filename);
        if(lines<0){
            fprintf(stderr,"No such file or directory");
            exit(EXIT_FAILURE);
        }

        configs = malloc(sizeof(conf)*lines);
        init_config(configs,filename);
        chdir(cwd);
        sandb_init(child,firstarg,execArgs);
    }

    else{
        fprintf(stderr,"Must provide config file");
    }

    
    return 0;
}