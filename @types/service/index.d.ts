declare namespace Service {
  
  export type JsonMessageContext = {
    type: "success" | "error";
    message: "Unauthorized" | "Transaction successful";
    data: any;
  };

}
